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
        Assert.Equal("active", SimCatalog.FirewallActive.HaState);
        Assert.Equal("passive", SimCatalog.FirewallPassive.HaState);
        Assert.Equal("passive", SimCatalog.FirewallActive.HaPeerState);
        Assert.Equal(SimCatalog.FirewallActive.Location, SimCatalog.FirewallPassive.Location);
        Assert.Contains(SimCatalog.DefaultAgents, item => item.Device == SimCatalog.FirewallActive);
        Assert.All(devices.Where(device => device.SysName is not ("sim-fw-01" or "sim-fw-02")), device => Assert.Null(device.HaState));
    }

    [Fact(Timeout = 20000)]
    public async Task Walk_reads_sensors_and_cpu_and_stops_at_the_subtree()
    {
        using var agent = new SimSnmpAgent();
        agent.Start();
        var client = new SnmpWalkClient();
        var target = Target(agent.Port, "public");

        var sensors = await client.WalkAsync(target, "1.3.6.1.2.1.99.1.1.1.4", 100, CancellationToken.None);
        Assert.True(sensors.Ok, sensors.Error);
        Assert.False(sensors.Truncated);
        Assert.Equal(2, sensors.Rows.Count);
        var inlet = sensors.Rows.Single(row => row.Oid.EndsWith(".4.1", StringComparison.Ordinal));
        Assert.Equal("Inlet Temp", inlet.Label);
        Assert.Equal("Inlet Temp", inlet.SuggestedName);
        Assert.Equal("celsius", inlet.SensorType);
        Assert.Equal("units", inlet.Scale);
        Assert.Equal("Integer32", inlet.Type);
        Assert.Equal("36", inlet.Value);
        Assert.True(inlet.Numeric);
        Assert.Equal("gauge", inlet.Kind);
        Assert.Equal("C", inlet.Unit);
        Assert.Contains(sensors.Rows, row => row.Label == "Exhaust Temp" && row.Value == "44");

        var cpu = await client.WalkAsync(target, ".1.3.6.1.2.1.25.3.3.1.2", 20, CancellationToken.None);
        Assert.True(cpu.Ok, cpu.Error);
        Assert.False(cpu.Truncated);
        Assert.Equal("Management plane CPU", cpu.Rows.Single(row => row.Oid.EndsWith(".2.1", StringComparison.Ordinal)).SuggestedName);
        Assert.Equal("Data plane CPU", cpu.Rows.Single(row => row.Oid.EndsWith(".2.2", StringComparison.Ordinal)).SuggestedName);

        var system = await client.WalkAsync(target, "1.3.6.1.2.1.1", 100, CancellationToken.None);
        Assert.True(system.Ok, system.Error);
        Assert.False(system.Truncated);
        Assert.NotEmpty(system.Rows);
        Assert.All(system.Rows, row => Assert.StartsWith("1.3.6.1.2.1.1.", row.Oid, StringComparison.Ordinal));
        Assert.Contains(system.Rows, row => row.SuggestedName == "sysName" && row.Value == "sim-core-01");

        var capped = await client.WalkAsync(target, "1.3.6.1.2.1", 3, CancellationToken.None);
        Assert.True(capped.Ok, capped.Error);
        Assert.Equal(3, capped.Rows.Count);
        Assert.True(capped.Truncated);
        Assert.Equal("rows", capped.Limit);
        Assert.All(capped.Rows, row => Assert.StartsWith("1.3.6.1.2.1.", row.Oid, StringComparison.Ordinal));

        var v1 = await client.WalkAsync(target with { Version = SnmpVersion.V1 }, "1.3.6.1.2.1.25.3.3.1.2", 20, CancellationToken.None);
        Assert.True(v1.Ok, v1.Error);
        Assert.Equal(2, v1.Rows.Count);
        Assert.Contains(v1.Rows, row => row.SuggestedName == "Data plane CPU");

        var dead = await client.WalkAsync(
            target with { Community = "secret-community", Port = 1, TimeoutMs = 400, Retries = 0 },
            "1.3.6.1.2.1.1",
            10,
            CancellationToken.None);
        Assert.False(dead.Ok);
        Assert.Contains("127.0.0.1", dead.Error);
        Assert.DoesNotContain("secret-community", dead.Error);
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
