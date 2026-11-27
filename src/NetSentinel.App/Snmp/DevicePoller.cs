using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using NetSentinel.Core;

namespace NetSentinel.Snmp;

public sealed class DevicePoller
{
    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysUpTime = "1.3.6.1.2.1.1.3.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string IfTable = "1.3.6.1.2.1.2.2";
    public const string IfXTable = "1.3.6.1.2.1.31.1.1";
    public const string IfEntry = "1.3.6.1.2.1.2.2.1";
    public const string IfXEntry = "1.3.6.1.2.1.31.1.1.1";
    public const string LldpRemTable = "1.0.8802.1.1.2.1.4.1";
    public const string LldpLocPortTable = "1.0.8802.1.1.2.1.3.7";
    public const string CdpCacheTable = "1.3.6.1.4.1.9.9.23.1.2.1";

    private readonly ILogger<DevicePoller> _logger;

    public DevicePoller(ILogger<DevicePoller> logger)
    {
        _logger = logger;
    }

    public async Task<PollResult> PollAsync(DevicePollTarget target, CancellationToken cancellationToken)
    {
        var timeout = Math.Clamp(target.TimeoutMs, 200, 30_000);
        var retries = Math.Clamp(target.Retries, 0, 5);
        var pingTask = PingAsync(target.Host, Math.Min(timeout, 1500), cancellationToken);

        PollResult? last = null;
        for (var attempt = 0; attempt <= retries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            last = await Task.Run(() => PollSnmp(target, timeout), cancellationToken);
            if (last.SnmpOk || attempt == retries)
            {
                break;
            }
        }

        last ??= new PollResult { Error = "SNMP poll did not run." };
        last.PingOk = await pingTask;
        return last;
    }

    private PollResult PollSnmp(DevicePollTarget target, int timeout)
    {
        var result = new PollResult();
        try
        {
            var endpoint = Resolve(target.Host, target.Port);
            var watch = Stopwatch.StartNew();
            ISnmpMessage? report = null;
            IPrivacyProvider? privacy = null;
            if (target.Version == SnmpVersion.V3)
            {
                privacy = SnmpPrivacy.Create(target.V3AuthProtocol, target.V3AuthPassword, target.V3PrivProtocol, target.V3PrivPassword);
                report = Discover(endpoint, timeout);
            }

            var system = Get(target, endpoint, timeout, new[] { SysDescr, SysUpTime, SysName }, ref report, privacy);
            watch.Stop();
            result.ResponseTimeMs = (int)Math.Min(int.MaxValue, watch.ElapsedMilliseconds);
            var byOid = system.GroupBy(v => v.Id.ToString()).ToDictionary(g => g.Key, g => g.Last().Data);

            if (byOid.TryGetValue(SysDescr, out var descr) && !SnmpValues.IsException(descr))
            {
                result.SysDescr = Trim(SnmpValues.Format(descr), 500);
            }

            if (byOid.TryGetValue(SysName, out var name) && !SnmpValues.IsException(name))
            {
                result.SysName = Trim(SnmpValues.Format(name), 200);
            }

            if (byOid.TryGetValue(SysUpTime, out var uptime) && SnmpValues.AsUnsigned(uptime) is ulong ticks)
            {
                result.SysUpTimeTicks = (long)ticks;
            }

            try
            {
                var identity = Get(target, endpoint, timeout, new[] { SysObjectId }, ref report, privacy);
                var objectId = identity.FirstOrDefault()?.Data;
                if (objectId is not null && !SnmpValues.IsException(objectId))
                {
                    result.SysObjectId = Trim(SnmpValues.Format(objectId), 200);
                }

                _logger.LogDebug("sysObjectID {Host} {Oid}", target.Host, result.SysObjectId ?? "(none)");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "sysObjectID read failed for {Host}", target.Host);
            }

            try
            {
                var ha = ReadHa(target, endpoint, timeout, result.SysObjectId, result.SysDescr, ref report, privacy);
                result.HaState = ha.Token;
                result.HaPeerState = ha.Peer;
                result.HaVendor = ha.Vendor;
                result.HaRead = true;
                result.HaProbeFailed = ha.ProbeFailed;
                _logger.LogDebug(
                    "HA result {Host} vendor={Vendor} state={State} peer={Peer} probeFailed={ProbeFailed}",
                    target.Host,
                    ha.Vendor ?? "(none)",
                    ha.Label,
                    ha.Peer ?? "(none)",
                    ha.ProbeFailed);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "HA poll failed for {Host}", target.Host);
                result.HaRead = true;
                result.HaProbeFailed = true;
            }

            List<Variable> ifTable;
            List<Variable> ifX = new();
            try
            {
                ifTable = Walk(target, endpoint, timeout, IfTable, ref report, privacy);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Interface table walk failed for {Host}", target.Host);
                ifTable = new List<Variable>();
            }

            if (target.Version != SnmpVersion.V1)
            {
                try
                {
                    ifX = Walk(target, endpoint, timeout, IfXTable, ref report, privacy);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "ifXTable walk failed for {Host}", target.Host);
                }
            }

            result.Interfaces = BuildInterfaces(ifTable, ifX);
            result.SampledAt = DateTime.UtcNow;
            result.CustomOids = ReadCustom(target, endpoint, timeout, ref report, privacy);
            result.Neighbors = ReadNeighbors(target, endpoint, timeout, ref report, privacy);
            result.SnmpOk = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result.SnmpOk = false;
            result.Error = Trim(ex.Message, 300);
            result.SampledAt = DateTime.UtcNow;
            _logger.LogDebug(ex, "SNMP poll failed for {Host}:{Port}", target.Host, target.Port);
        }

        return result;
    }

    private static List<CustomOidReading> ReadCustom(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        ref ISnmpMessage? report,
        IPrivacyProvider? privacy)
    {
        var readings = new List<CustomOidReading>();
        foreach (var custom in target.CustomOids)
        {
            var reading = new CustomOidReading { Id = custom.Id, Name = custom.Name, Oid = custom.Oid };
            if (!IsOid(custom.Oid))
            {
                reading.RawValue = "invalid OID";
                readings.Add(reading);
                continue;
            }

            try
            {
                var variables = Get(target, endpoint, timeout, new[] { custom.Oid }, ref report, privacy);
                var data = variables.FirstOrDefault()?.Data;
                if (data is null || SnmpValues.IsException(data))
                {
                    reading.RawValue = data is null ? "no response" : SnmpValues.Format(data);
                }
                else
                {
                    reading.Ok = true;
                    reading.RawValue = Trim(SnmpValues.Format(data), 500);
                    reading.NumericValue = SnmpValues.AsDouble(data);
                    reading.CounterBits = SnmpValues.CounterWidth(data);
                }
            }
            catch (Exception ex)
            {
                reading.RawValue = Trim(ex.Message, 200);
            }

            readings.Add(reading);
        }

        return readings;
    }

    private List<NeighborObservation> ReadNeighbors(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        ref ISnmpMessage? report,
        IPrivacyProvider? privacy)
    {
        var bindings = new List<SnmpBinding>();
        foreach (var root in new[] { LldpRemTable, LldpLocPortTable, CdpCacheTable })
        {
            try
            {
                foreach (var variable in Walk(target, endpoint, timeout, root, ref report, privacy))
                {
                    bindings.Add(new SnmpBinding(variable.Id.ToString(), FormatNeighborValue(variable)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Neighbor walk {Root} failed for {Host}", root, target.Host);
            }
        }

        return NeighborTables.Parse(bindings);
    }

    private HaReading ReadHa(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        string? sysObjectId,
        string? sysDescr,
        ref ISnmpMessage? report,
        IPrivacyProvider? privacy)
    {
        var reportBox = report;
        var privacyBox = privacy;
        var vendors = HaStatus.ForDevice(sysObjectId, sysDescr);
        _logger.LogDebug("HA probe {Host} vendors={Vendors}", target.Host, string.Join(",", vendors.Select(vendor => vendor.Id)));
        var reading = HaStatus.Resolve(
            oids => Probe(target, endpoint, timeout, oids, ref reportBox, ref privacyBox),
            vendors);
        report = reportBox;
        privacy = privacyBox;
        return reading;
    }

    private HaProbeAnswer Probe(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        IReadOnlyList<string> oids,
        ref ISnmpMessage? report,
        ref IPrivacyProvider? privacy)
    {
        foreach (var oid in oids.Where(item => item.EndsWith(".0", StringComparison.Ordinal)))
        {
            if (TryGet(target, endpoint, timeout, oid, ref report, ref privacy) is string value)
            {
                return new HaProbeAnswer(true, value);
            }
        }

        foreach (var oid in oids)
        {
            var baseOid = oid.EndsWith(".0", StringComparison.Ordinal) ? oid[..^2] : oid;
            if (TryGetNext(target, endpoint, timeout, baseOid, ref report, ref privacy) is string value)
            {
                return new HaProbeAnswer(true, value);
            }
        }

        return new HaProbeAnswer(false, null);
    }

    private string? TryGet(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        string oid,
        ref ISnmpMessage? report,
        ref IPrivacyProvider? privacy)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                var variables = Get(target, endpoint, timeout, new[] { oid }, ref report, privacy);
                var variable = variables.FirstOrDefault();
                var text = Describe(variable);
                _logger.LogDebug("HA GET {Host} {Oid} -> {Value}", target.Host, oid, text ?? "(no variable)");
                if (variable is null || SnmpValues.IsException(variable.Data) || HaStatus.IsMissingToken(text))
                {
                    return null;
                }

                return Trim(text, 80);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "HA GET {Host} {Oid} failed{Retry}", target.Host, oid, attempt == 1 ? "; retrying" : "");
            }
        }

        return null;
    }

    private string? TryGetNext(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        string baseOid,
        ref ISnmpMessage? report,
        ref IPrivacyProvider? privacy)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                var variables = GetNext(target, endpoint, timeout, baseOid, ref report, ref privacy);
                var variable = variables.FirstOrDefault();
                var returned = variable?.Id.ToString();
                var text = Describe(variable);
                _logger.LogDebug("HA GETNEXT {Host} {Base} -> {Oid} {Value}", target.Host, baseOid, returned ?? "(none)", text ?? "(none)");
                if (variable is null || string.IsNullOrEmpty(returned) || SnmpValues.IsException(variable.Data) || HaStatus.IsMissingToken(text))
                {
                    return null;
                }

                if (!returned.Equals(baseOid, StringComparison.Ordinal)
                    && !returned.StartsWith(baseOid + ".", StringComparison.Ordinal))
                {
                    return null;
                }

                return Trim(text, 80);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "HA GETNEXT {Host} {Base} failed{Retry}", target.Host, baseOid, attempt == 1 ? "; retrying" : "");
            }
        }

        return null;
    }

    private static string? Describe(Variable? variable)
        => variable is null ? null : SnmpValues.Format(variable.Data);

    private static IList<Variable> GetNext(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        string oid,
        ref ISnmpMessage? report,
        ref IPrivacyProvider? privacy)
    {
        var variables = new List<Variable> { new(new ObjectIdentifier(oid)) };
        ISnmpMessage reply;
        if (target.Version == SnmpVersion.V3)
        {
            report ??= Discover(endpoint, timeout);
            privacy ??= SnmpPrivacy.Create(target.V3AuthProtocol, target.V3AuthPassword, target.V3PrivProtocol, target.V3PrivPassword);
            var request = new GetNextRequestMessage(
                VersionCode.V3,
                Messenger.NextMessageId,
                Messenger.NextRequestId,
                new OctetString(target.V3User),
                new OctetString(target.V3Context ?? ""),
                variables,
                privacy,
                Messenger.MaxMessageSize,
                report);
            reply = request.GetResponse(timeout, endpoint);
        }
        else
        {
            var version = target.Version == SnmpVersion.V1 ? VersionCode.V1 : VersionCode.V2;
            var request = new GetNextRequestMessage(
                Messenger.NextRequestId,
                version,
                new OctetString(target.Community ?? ""),
                variables);
            reply = request.GetResponse(timeout, endpoint);
        }

        EnsureOk(reply);
        return reply.Pdu().Variables;
    }

    private static string FormatNeighborValue(Variable variable)
    {
        if (variable.Data is OctetString text)
        {
            var raw = text.GetRaw();
            if (raw.Length == 4 && raw.Any(b => b < 32 || b > 126))
            {
                return string.Join('.', raw);
            }

            if (raw.Length == 6)
            {
                return string.Join(':', raw.Select(b => b.ToString("x2")));
            }
        }

        return SnmpValues.Format(variable.Data);
    }

    private static List<InterfaceReading> BuildInterfaces(IEnumerable<Variable> ifTable, IEnumerable<Variable> ifX)
    {
        var rows = new Dictionary<int, MutableInterface>();

        MutableInterface Ensure(int index)
        {
            if (!rows.TryGetValue(index, out var row))
            {
                row = new MutableInterface { IfIndex = index };
                rows[index] = row;
            }

            return row;
        }

        foreach (var variable in ifTable)
        {
            if (!TryColumn(variable.Id.ToString(), IfEntry, out var column, out var index))
            {
                continue;
            }

            var row = Ensure(index);
            switch (column)
            {
                case 2:
                    row.Descr = SnmpValues.Format(variable.Data);
                    break;
                case 5:
                    row.Speed = SnmpValues.AsUnsigned(variable.Data) ?? 0;
                    break;
                case 7:
                    row.Admin = (int)(SnmpValues.AsUnsigned(variable.Data) ?? 0);
                    break;
                case 8:
                    row.Oper = (int)(SnmpValues.AsUnsigned(variable.Data) ?? 0);
                    break;
                case 10:
                    row.In32 = SnmpValues.AsUnsigned(variable.Data);
                    break;
                case 16:
                    row.Out32 = SnmpValues.AsUnsigned(variable.Data);
                    break;
            }
        }

        foreach (var variable in ifX)
        {
            if (!TryColumn(variable.Id.ToString(), IfXEntry, out var column, out var index))
            {
                continue;
            }

            var row = Ensure(index);
            switch (column)
            {
                case 1:
                    row.Name = SnmpValues.Format(variable.Data);
                    break;
                case 6:
                    row.HcIn = SnmpValues.AsUnsigned(variable.Data);
                    break;
                case 10:
                    row.HcOut = SnmpValues.AsUnsigned(variable.Data);
                    break;
                case 15:
                    row.HighSpeedMbps = SnmpValues.AsUnsigned(variable.Data);
                    break;
                case 18:
                    row.Alias = SnmpValues.Format(variable.Data);
                    break;
            }
        }

        return rows.Values
            .OrderBy(row => row.IfIndex)
            .Select(row => row.ToReading())
            .ToList();
    }

    internal static bool TryColumn(string oid, string entryPrefix, out int column, out int ifIndex)
    {
        column = 0;
        ifIndex = 0;
        var prefix = entryPrefix + ".";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = oid[prefix.Length..].Split('.');
        if (parts.Length != 2)
        {
            return false;
        }

        return int.TryParse(parts[0], out column) && int.TryParse(parts[1], out ifIndex);
    }

    private static IList<Variable> Get(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        IReadOnlyList<string> oids,
        ref ISnmpMessage? report,
        IPrivacyProvider? privacy)
    {
        var variables = oids.Select(oid => new Variable(new ObjectIdentifier(oid))).ToList();
        ISnmpMessage reply;
        if (target.Version == SnmpVersion.V3)
        {
            report ??= Discover(endpoint, timeout);
            privacy ??= SnmpPrivacy.Create(target.V3AuthProtocol, target.V3AuthPassword, target.V3PrivProtocol, target.V3PrivPassword);
            var request = new GetRequestMessage(
                VersionCode.V3,
                Messenger.NextMessageId,
                Messenger.NextRequestId,
                new OctetString(target.V3User),
                new OctetString(target.V3Context ?? ""),
                variables,
                privacy,
                Messenger.MaxMessageSize,
                report);
            reply = request.GetResponse(timeout, endpoint);
        }
        else
        {
            var version = target.Version == SnmpVersion.V1 ? VersionCode.V1 : VersionCode.V2;
            var request = new GetRequestMessage(
                Messenger.NextRequestId,
                version,
                new OctetString(target.Community ?? ""),
                variables);
            reply = request.GetResponse(timeout, endpoint);
        }

        EnsureOk(reply);
        return reply.Pdu().Variables;
    }

    private static List<Variable> Walk(
        DevicePollTarget target,
        IPEndPoint endpoint,
        int timeout,
        string root,
        ref ISnmpMessage? report,
        IPrivacyProvider? privacy)
    {
        var list = new List<Variable>();
        var table = new ObjectIdentifier(root);
        if (target.Version == SnmpVersion.V1)
        {
            Messenger.Walk(
                VersionCode.V1,
                endpoint,
                new OctetString(target.Community ?? ""),
                table,
                list,
                timeout,
                WalkMode.WithinSubtree);
            return list;
        }

        if (target.Version == SnmpVersion.V3)
        {
            report ??= Discover(endpoint, timeout);
            privacy ??= SnmpPrivacy.Create(target.V3AuthProtocol, target.V3AuthPassword, target.V3PrivProtocol, target.V3PrivPassword);
            Messenger.BulkWalk(
                VersionCode.V3,
                endpoint,
                new OctetString(target.V3User),
                new OctetString(target.V3Context ?? ""),
                table,
                list,
                timeout,
                10,
                WalkMode.WithinSubtree,
                privacy,
                report);
            return list;
        }

        Messenger.BulkWalk(
            VersionCode.V2,
            endpoint,
            new OctetString(target.Community ?? ""),
            new OctetString(string.Empty),
            table,
            list,
            timeout,
            10,
            WalkMode.WithinSubtree,
            null,
            null);
        return list;
    }

    private static ISnmpMessage Discover(IPEndPoint endpoint, int timeout)
    {
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        return discovery.GetResponse(timeout, endpoint);
    }

    private static void EnsureOk(ISnmpMessage reply)
    {
        if (reply is ReportMessage)
        {
            var ids = string.Join(", ", reply.Variables().Select(v => v.Id.ToString()));
            throw new InvalidOperationException($"SNMP report: {ids}");
        }

        var status = reply.Pdu().ErrorStatus.ToErrorCode();
        if (status != ErrorCode.NoError)
        {
            throw new InvalidOperationException($"SNMP error {status} at index {reply.Pdu().ErrorIndex.ToInt32()}.");
        }
    }

    private static IPEndPoint Resolve(string host, int port)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            return new IPEndPoint(address, port);
        }

        var addresses = Dns.GetHostAddresses(host);
        var ipv4 = addresses.FirstOrDefault(item => item.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
        if (ipv4 is null)
        {
            throw new InvalidOperationException($"Could not resolve {host}.");
        }

        return new IPEndPoint(ipv4, port);
    }

    private static async Task<bool?> PingAsync(string host, int timeout, CancellationToken cancellationToken)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(host, timeout);
            return reply.Status == IPStatus.Success;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static bool IsOid(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 200 || text.StartsWith('.') || text.EndsWith('.'))
        {
            return false;
        }

        var parts = text.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 10 || !part.All(char.IsDigit))
            {
                return false;
            }
        }

        return parts[0] is "0" or "1" or "2";
    }

    private static string Trim(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        return value.Length <= max ? value : value[..max];
    }

    private sealed class MutableInterface
    {
        public int IfIndex { get; set; }
        public string Descr { get; set; } = "";
        public string Name { get; set; } = "";
        public string Alias { get; set; } = "";
        public int Admin { get; set; }
        public int Oper { get; set; }
        public ulong Speed { get; set; }
        public ulong? In32 { get; set; }
        public ulong? Out32 { get; set; }
        public ulong? HcIn { get; set; }
        public ulong? HcOut { get; set; }
        public ulong? HighSpeedMbps { get; set; }

        public InterfaceReading ToReading()
        {
            var use64 = HcIn is not null && HcOut is not null;
            ulong speed = 0;
            if (HighSpeedMbps is > 0 and <= 10_000_000)
            {
                speed = HighSpeedMbps.Value * 1_000_000UL;
            }
            else if (Speed > 0)
            {
                speed = Speed;
            }

            return new InterfaceReading
            {
                IfIndex = IfIndex,
                IfDescr = string.IsNullOrWhiteSpace(Descr) ? Name : Descr,
                IfName = Name,
                IfAlias = Alias,
                AdminStatus = Admin,
                OperStatus = Oper,
                SpeedBps = speed,
                InOctets = use64 ? HcIn!.Value : In32 ?? 0,
                OutOctets = use64 ? HcOut!.Value : Out32 ?? 0,
                CounterBits = use64 ? 64 : 32
            };
        }
    }
}
