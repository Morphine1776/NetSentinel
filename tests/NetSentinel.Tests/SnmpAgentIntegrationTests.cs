using System.Net;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NetSentinel.Core;
using NetSentinel.SimAgent;
using NetSentinel.Snmp;

namespace NetSentinel.Tests;

public class SnmpAgentIntegrationTests
{
    [Fact(Timeout = 20000)]
    public async Task Poller_reads_system_and_interface_counters_from_the_simulator()
    {
        using var agent = new SimSnmpAgent();
        agent.Start();
        var poller = new DevicePoller(NullLogger<DevicePoller>.Instance);
        var target = Target(agent.Port, "public");

        var first = await poller.PollAsync(target, CancellationToken.None);
        await Task.Delay(1200);
        var second = await poller.PollAsync(target, CancellationToken.None);

        Assert.True(first.SnmpOk, first.Error);
        Assert.Equal("sim-core-01", first.SysName);
        Assert.Contains("Simulator", first.SysDescr);
        Assert.NotNull(first.SysUpTimeTicks);
        Assert.Equal(4, first.Interfaces.Count);

        var uplink = second.Interfaces.Single(iface => iface.IfDescr == "Gi0/0");
        var spare = second.Interfaces.Single(iface => iface.IfDescr == "Gi0/2");
        Assert.Equal(64, uplink.CounterBits);
        Assert.Equal(1, uplink.OperStatus);
        Assert.Equal(1_000_000_000ul, uplink.SpeedBps);
        Assert.Equal(2, spare.OperStatus);
        Assert.Equal(1, spare.AdminStatus);

        var before = first.Interfaces.Single(iface => iface.IfDescr == "Gi0/0");
        Assert.True(uplink.InOctets > before.InOctets);
        var elapsed = (second.SampledAt - first.SampledAt).TotalSeconds;
        var bps = CounterMath.BitsPerSecond(before.InOctets, uplink.InOctets, uplink.CounterBits, elapsed, uptimeReset: false);
        Assert.NotNull(bps);
        Assert.InRange(bps.Value, 90_000_000, 110_000_000);

        var wrong = await poller.PollAsync(target with { Community = "nope", TimeoutMs = 600, Retries = 0 }, CancellationToken.None);
        Assert.False(wrong.SnmpOk);
    }

    [Fact(Timeout = 15000)]
    public async Task Simulator_trap_is_parsed_as_a_cold_start()
    {
        using var agent = new SimSnmpAgent();
        agent.Start();
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
        agent.SendTrap(port);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var packet = await receiver.ReceiveAsync(timeout.Token);
        var traps = SnmpTrapParser.Parse(packet.Buffer, new UserRegistry());
        var trap = Assert.Single(traps);
        Assert.Equal("1.3.6.1.6.3.1.1.5.1", trap.TrapOid);
        Assert.Contains("1.3.6.1.4.1.99999.1.0", trap.Varbinds);
        Assert.Equal("v2c", trap.Version);
        Assert.Null(trap.LinkEvent);
    }

    [Fact]
    public void Link_down_trap_carries_the_interface_index()
    {
        var variables = new List<Variable>
        {
            new(new ObjectIdentifier("1.3.6.1.2.1.2.2.1.1.14"), new Integer32(14)),
            new(new ObjectIdentifier("1.3.6.1.2.1.2.2.1.2.14"), new OctetString("Gi1/0/12")),
            new(new ObjectIdentifier("1.3.6.1.2.1.2.2.1.8.14"), new Integer32(2))
        };
        var message = new TrapV2Message(
            7,
            VersionCode.V2,
            new OctetString("public"),
            new ObjectIdentifier("1.3.6.1.6.3.1.1.5.3"),
            100,
            variables);
        var trap = Assert.Single(SnmpTrapParser.Parse(message.ToBytes(), new UserRegistry()));
        Assert.Equal("down", trap.LinkEvent);
        Assert.Equal(14, trap.IfIndex);
    }

    [Fact]
    public void Demo_catalog_spans_locations_with_one_partly_down()
    {
        var devices = SimCatalog.DefaultAgents.Select(item => item.Device).ToList();
        var locations = devices
            .Select(device => device.Location.Trim().ToUpperInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToList();
        Assert.True(locations.Count >= 3);
        Assert.Equal(devices.Count, SimCatalog.DefaultAgents.Select(item => item.Port).Distinct().Count());

        var mixed = devices
            .GroupBy(device => device.Location.Trim(), StringComparer.OrdinalIgnoreCase)
            .Any(group => group.Any(device => device.Answers) && group.Any(device => !device.Answers));
        Assert.True(mixed);
        Assert.Contains(devices, device => !device.Answers && device.Location == "Closet");
        Assert.Contains(devices, device => device.Answers && device.Location == "MDF");
        Assert.Contains(devices, device => device.Answers && device.Location == "IDF-2");
    }

    [Fact]
    public void Access_simulator_exposes_a_full_edge_of_ports()
    {
        Assert.Equal(26, SimCatalog.Access.Ports.Count);
        Assert.Contains(SimCatalog.Access.Ports, port => port.Name == "Gi0/1" && port.Alias == "uplink");
        Assert.Equal(24, SimCatalog.Access.Ports.Count(port => port.Name.StartsWith("Gi1/0/", StringComparison.Ordinal)));
        Assert.Contains(SimCatalog.Access.Ports, port => port.Admin == 2 && port.Oper == 2);
        Assert.Contains(SimCatalog.Access.Ports, port => port.Name == "Gi1/0/21" && port.Oper == 2 && port.Admin == 1);
    }

    private static DevicePollTarget Target(int port, string community) => new(
        "127.0.0.1",
        port,
        SnmpVersion.V2C,
        community,
        "",
        "",
        "None",
        "",
        "None",
        "",
        Array.Empty<CustomOidTarget>(),
        2000,
        0);
}
