using System.Net;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace NetSentinel.SimAgent;

/// <summary>
/// A small SNMP v1/v2c agent used for development, screenshots, and tests.
/// It exposes system scalars, interface counters, and an optional gauge.
/// The default core device has four interfaces. The access catalog adds a full Gi1/0/1–24 edge.
/// </summary>
public sealed class SimSnmpAgent : IDisposable
{
    private readonly int _requestedPort;
    private readonly string _community;
    private readonly SimDevice _device;
    private readonly DateTime _started = DateTime.UtcNow;
    private readonly List<SimObject> _entries = new();
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public SimSnmpAgent(int port = 0, string community = "public")
        : this(port, community, SimCatalog.Core)
    {
    }

    public SimSnmpAgent(int port, string community, SimDevice device)
    {
        _requestedPort = port;
        _community = community;
        _device = device;
        BuildMib();
    }

    public string SysName => _device.SysName;

    public string Location => _device.Location;

    public bool Answers => _device.Answers;

    public int Port { get; private set; }

    public void Start()
    {
        if (_udp is not null)
        {
            return;
        }

        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Loopback, _requestedPort));
        Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => ReceiveLoop(_cts.Token));
    }

    public void SendTrap(int trapPort, string trapOid = "1.3.6.1.6.3.1.1.5.1")
    {
        SendTrap(new IPEndPoint(IPAddress.Loopback, trapPort), trapOid);
    }

    public void SendTrap(IPEndPoint receiver, string trapOid = "1.3.6.1.6.3.1.1.5.1")
    {
        var variables = new List<Variable>
        {
            new(new ObjectIdentifier("1.3.6.1.4.1.99999.1.0"), new Gauge32(Temperature()))
        };
        Messenger.SendTrapV2(
            requestId: Random.Shared.Next(1, int.MaxValue),
            version: VersionCode.V2,
            receiver: receiver,
            community: new OctetString(_community),
            enterprise: new ObjectIdentifier(trapOid),
            timestamp: Uptime(),
            variables: variables);
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _udp?.Dispose();
        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
        }

        _cts?.Dispose();
        _udp = null;
    }

    private async Task ReceiveLoop(CancellationToken cancellationToken)
    {
        var udp = _udp;
        if (udp is null)
        {
            return;
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await udp.ReceiveAsync(cancellationToken);
            }
            catch (Exception) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }

            try
            {
                Handle(udp, result);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"simulator request failed: {ex.Message}");
            }
        }
    }

    private void Handle(UdpClient udp, UdpReceiveResult result)
    {
        if (!_device.Answers)
        {
            return;
        }

        IList<ISnmpMessage> messages;
        try
        {
            messages = MessageFactory.ParseMessages(result.Buffer, 0, result.Buffer.Length, new UserRegistry());
        }
        catch (Exception)
        {
            return;
        }

        foreach (var message in messages)
        {
            if (message.Version is not (VersionCode.V1 or VersionCode.V2))
            {
                continue;
            }

            string community;
            try
            {
                community = message.Community().ToString();
            }
            catch (Exception)
            {
                continue;
            }

            if (!string.Equals(community, _community, StringComparison.Ordinal))
            {
                continue;
            }

            var type = message.TypeCode();
            if (type is not (SnmpType.GetRequestPdu or SnmpType.GetNextRequestPdu or SnmpType.GetBulkRequestPdu))
            {
                if (type == SnmpType.SetRequestPdu)
                {
                    var denied = new ResponseMessage(
                        message.RequestId(),
                        message.Version,
                        message.Community(),
                        ErrorCode.ReadOnly,
                        1,
                        message.Variables());
                    udp.Send(denied.ToBytes(), denied.ToBytes().Length, result.RemoteEndPoint);
                }

                continue;
            }

            var (variables, error, index) = Answer(message);
            var response = new ResponseMessage(
                message.RequestId(),
                message.Version,
                message.Community(),
                error,
                index,
                variables);
            var bytes = response.ToBytes();
            udp.Send(bytes, bytes.Length, result.RemoteEndPoint);
        }
    }

    private (IList<Variable> Variables, ErrorCode Error, int Index) Answer(ISnmpMessage message)
    {
        var pdu = message.Pdu();
        var version = message.Version;
        if (message.TypeCode() == SnmpType.GetBulkRequestPdu)
        {
            return (Bulk(pdu, version), ErrorCode.NoError, 0);
        }

        if (message.TypeCode() == SnmpType.GetNextRequestPdu)
        {
            var list = new List<Variable>();
            for (var i = 0; i < pdu.Variables.Count; i++)
            {
                var next = Next(pdu.Variables[i].Id);
                if (next is null)
                {
                    return (pdu.Variables, ErrorCode.NoSuchName, i + 1);
                }

                list.Add(next);
            }

            return (list, ErrorCode.NoError, 0);
        }

        var values = new List<Variable>();
        for (var i = 0; i < pdu.Variables.Count; i++)
        {
            var exact = FindExact(pdu.Variables[i].Id);
            if (exact >= 0)
            {
                values.Add(new Variable(_entries[exact].Oid, _entries[exact].Read()));
                continue;
            }

            if (version == VersionCode.V1)
            {
                return (pdu.Variables, ErrorCode.NoSuchName, i + 1);
            }

            values.Add(new Variable(pdu.Variables[i].Id, new NoSuchObject()));
        }

        return (values, ErrorCode.NoError, 0);
    }

    private List<Variable> Bulk(ISnmpPdu pdu, VersionCode version)
    {
        var nonRepeaters = Math.Max(0, pdu.ErrorStatus.ToInt32());
        var repetitions = pdu.ErrorIndex.ToInt32();
        if (repetitions < 1)
        {
            repetitions = 1;
        }

        if (repetitions > 25)
        {
            repetitions = 25;
        }

        var result = new List<Variable>();
        var count = Math.Min(nonRepeaters, pdu.Variables.Count);
        for (var i = 0; i < count; i++)
        {
            result.Add(NextOrEnd(pdu.Variables[i].Id, version));
        }

        for (var i = count; i < pdu.Variables.Count; i++)
        {
            var current = pdu.Variables[i].Id;
            for (var repeat = 0; repeat < repetitions; repeat++)
            {
                var next = NextOrEnd(current, version);
                result.Add(next);
                if (next.Data.TypeCode == SnmpType.EndOfMibView)
                {
                    break;
                }

                current = next.Id;
            }
        }

        return result;
    }

    private Variable NextOrEnd(ObjectIdentifier oid, VersionCode version)
    {
        var next = Next(oid);
        if (next is not null)
        {
            return next;
        }

        return version == VersionCode.V1
            ? new Variable(oid, new Null())
            : new Variable(oid, new EndOfMibView());
    }

    private Variable? Next(ObjectIdentifier oid)
    {
        var index = IndexOfNext(oid);
        if (index >= _entries.Count)
        {
            return null;
        }

        var entry = _entries[index];
        return new Variable(entry.Oid, entry.Read());
    }

    private int FindExact(ObjectIdentifier oid)
    {
        var lo = 0;
        var hi = _entries.Count - 1;
        while (lo <= hi)
        {
            var mid = (lo + hi) / 2;
            var compare = _entries[mid].Oid.CompareTo(oid);
            if (compare == 0)
            {
                return mid;
            }

            if (compare < 0)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return -1;
    }

    private int IndexOfNext(ObjectIdentifier oid)
    {
        var lo = 0;
        var hi = _entries.Count;
        while (lo < hi)
        {
            var mid = (lo + hi) / 2;
            if (_entries[mid].Oid.CompareTo(oid) <= 0)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        return lo;
    }

    private void BuildMib()
    {
        Add("1.3.6.1.2.1.1.1.0", () => new OctetString(_device.SysDescr));
        Add("1.3.6.1.2.1.1.2.0", () => new ObjectIdentifier("1.3.6.1.4.1.99999"));
        Add("1.3.6.1.2.1.1.3.0", () => new TimeTicks(Uptime()));
        Add("1.3.6.1.2.1.1.4.0", () => new OctetString("ops@netsentinel.local"));
        Add("1.3.6.1.2.1.1.5.0", () => new OctetString(_device.SysName));
        Add("1.3.6.1.2.1.1.6.0", () => new OctetString(_device.Location));
        Add("1.3.6.1.2.1.2.1.0", () => new Integer32(_device.Ports.Count));
        if (_device.IncludeGauge)
        {
            Add("1.3.6.1.4.1.99999.1.0", () => new Gauge32(Temperature()));
        }

        if (_device.IncludeSensors)
        {
            AddTemperature(1, "Inlet Temp", 36);
            AddTemperature(2, "Exhaust Temp", 44);
            Add("1.3.6.1.2.1.25.3.3.1.2.1", () => new Integer32(11));
            Add("1.3.6.1.2.1.25.3.3.1.2.2", () => new Integer32(24));
        }

        if (!string.IsNullOrWhiteSpace(_device.HaState))
        {
            Add("1.3.6.1.4.1.25461.2.1.2.1.11.0", () => new OctetString(_device.HaState));
            Add("1.3.6.1.4.1.25461.2.1.2.1.12.0", () => new OctetString(_device.HaPeerState ?? ""));
        }

        var interfaces = _device.Ports.Select(port => new SimInterface(
            port.Index,
            port.Name,
            port.Name,
            port.Alias,
            port.Name == "lo" ? 24 : 6,
            port.SpeedBps,
            port.HighSpeedMbps,
            port.Admin,
            port.Oper,
            port.InBytesPerSecond,
            port.OutBytesPerSecond)).ToArray();

        foreach (var iface in interfaces)
        {
            var index = iface.Index.ToString();
            Add($"1.3.6.1.2.1.2.2.1.1.{index}", () => new Integer32(iface.Index));
            Add($"1.3.6.1.2.1.2.2.1.2.{index}", () => new OctetString(iface.Descr));
            Add($"1.3.6.1.2.1.2.2.1.3.{index}", () => new Integer32(iface.IfType));
            Add($"1.3.6.1.2.1.2.2.1.4.{index}", () => new Integer32(1500));
            Add($"1.3.6.1.2.1.2.2.1.5.{index}", () => new Gauge32(iface.SpeedBps > uint.MaxValue ? uint.MaxValue : (uint)iface.SpeedBps));
            Add($"1.3.6.1.2.1.2.2.1.7.{index}", () => new Integer32(iface.Admin));
            Add($"1.3.6.1.2.1.2.2.1.8.{index}", () => new Integer32(iface.Oper));
            Add($"1.3.6.1.2.1.2.2.1.10.{index}", () => new Counter32((uint)(Octets(iface.InBytesPerSecond) & 0xFFFFFFFF)));
            Add($"1.3.6.1.2.1.2.2.1.16.{index}", () => new Counter32((uint)(Octets(iface.OutBytesPerSecond) & 0xFFFFFFFF)));
            Add($"1.3.6.1.2.1.31.1.1.1.1.{index}", () => new OctetString(iface.Name));
            Add($"1.3.6.1.2.1.31.1.1.1.6.{index}", () => new Counter64(Octets(iface.InBytesPerSecond)));
            Add($"1.3.6.1.2.1.31.1.1.1.10.{index}", () => new Counter64(Octets(iface.OutBytesPerSecond)));
            Add($"1.3.6.1.2.1.31.1.1.1.15.{index}", () => new Gauge32((uint)iface.HighSpeedMbps));
            Add($"1.3.6.1.2.1.31.1.1.1.18.{index}", () => new OctetString(iface.Alias));
            Add($"1.0.8802.1.1.2.1.3.7.1.3.{index}", () => new OctetString(iface.Name));
        }

        var neighborIndex = 1;
        foreach (var neighbor in _device.Lldp)
        {
            var suffix = $"0.{neighbor.LocalPort}.{neighborIndex}";
            Add($"1.0.8802.1.1.2.1.4.1.1.5.{suffix}", () => new OctetString(neighbor.RemoteName));
            Add($"1.0.8802.1.1.2.1.4.1.1.7.{suffix}", () => new OctetString(neighbor.RemotePort));
            Add($"1.0.8802.1.1.2.1.4.1.1.9.{suffix}", () => new OctetString(neighbor.RemoteName));
            if (!string.IsNullOrEmpty(neighbor.RemoteAddress))
            {
                Add($"1.0.8802.1.1.2.1.4.1.1.8.{suffix}", () => new OctetString(neighbor.RemoteAddress));
            }

            neighborIndex++;
        }

        neighborIndex = 1;
        foreach (var neighbor in _device.Cdp)
        {
            var suffix = $"{neighbor.LocalPort}.{neighborIndex}";
            Add($"1.3.6.1.4.1.9.9.23.1.2.1.1.6.{suffix}", () => new OctetString(neighbor.RemoteName));
            Add($"1.3.6.1.4.1.9.9.23.1.2.1.1.7.{suffix}", () => new OctetString(neighbor.RemotePort));
            if (IPAddress.TryParse(neighbor.RemoteAddress, out var address) && address.GetAddressBytes().Length == 4)
            {
                var bytes = address.GetAddressBytes();
                Add($"1.3.6.1.4.1.9.9.23.1.2.1.1.4.{suffix}", () => new OctetString(bytes));
            }

            neighborIndex++;
        }

        _entries.Sort((left, right) => left.Oid.CompareTo(right.Oid));
    }

    private void AddTemperature(int index, string name, int celsius)
    {
        Add($"1.3.6.1.2.1.47.1.1.1.1.7.{index}", () => new OctetString(name));
        Add($"1.3.6.1.2.1.99.1.1.1.1.{index}", () => new Integer32(8));
        Add($"1.3.6.1.2.1.99.1.1.1.2.{index}", () => new Integer32(9));
        Add($"1.3.6.1.2.1.99.1.1.1.4.{index}", () => new Integer32(celsius));
    }

    private void Add(string oid, Func<ISnmpData> read)
    {
        _entries.Add(new SimObject(new ObjectIdentifier(oid), read));
    }

    private uint Uptime()
    {
        var hundredths = (DateTime.UtcNow - _started).TotalMilliseconds / 10.0;
        return (uint)Math.Clamp(hundredths, 1, uint.MaxValue);
    }

    private uint Temperature()
    {
        var wave = 42 + (4 * Math.Sin((DateTime.UtcNow - _started).TotalSeconds / 6.0));
        return (uint)Math.Clamp(wave, 0, 100);
    }

    private ulong Octets(double bytesPerSecond)
    {
        if (bytesPerSecond <= 0)
        {
            return 10_000;
        }

        var elapsed = Math.Max(0, (DateTime.UtcNow - _started).TotalSeconds);
        return (ulong)(elapsed * bytesPerSecond);
    }

    private sealed class SimObject
    {
        public SimObject(ObjectIdentifier oid, Func<ISnmpData> read)
        {
            Oid = oid;
            Read = read;
        }

        public ObjectIdentifier Oid { get; }
        public Func<ISnmpData> Read { get; }
    }

    private sealed record SimInterface(
        int Index,
        string Descr,
        string Name,
        string Alias,
        int IfType,
        ulong SpeedBps,
        int HighSpeedMbps,
        int Admin,
        int Oper,
        double InBytesPerSecond,
        double OutBytesPerSecond);
}
