namespace NetSentinel.SimAgent;

public sealed class SimPort
{
    public int Index { get; init; }
    public string Name { get; init; } = "";
    public string Alias { get; init; } = "";
    public int Oper { get; init; } = 1;
    public int Admin { get; init; } = 1;
    public ulong SpeedBps { get; init; } = 1_000_000_000;
    public int HighSpeedMbps { get; init; } = 1000;
    public double InBytesPerSecond { get; init; }
    public double OutBytesPerSecond { get; init; }
}

public sealed class SimNeighbor
{
    public int LocalPort { get; init; }
    public string RemoteName { get; init; } = "";
    public string RemotePort { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
}

public sealed class SimDevice
{
    public string SysName { get; init; } = "";
    public string SysDescr { get; init; } = "NetSentinel Simulator";
    public string Location { get; init; } = "";
    public bool IncludeGauge { get; init; } = true;
    public bool IncludeSensors { get; init; }
    public bool Answers { get; init; } = true;
    public string? HaState { get; init; }
    public string? HaPeerState { get; init; }
    public IReadOnlyList<SimPort> Ports { get; init; } = Array.Empty<SimPort>();
    public IReadOnlyList<SimNeighbor> Lldp { get; init; } = Array.Empty<SimNeighbor>();
    public IReadOnlyList<SimNeighbor> Cdp { get; init; } = Array.Empty<SimNeighbor>();
}

public static class SimCatalog
{
    public static SimDevice Core { get; } = new()
    {
        SysName = "sim-core-01",
        SysDescr = "NetSentinel Simulator, virtual router",
        Location = "MDF",
        IncludeSensors = true,
        Ports = new[]
        {
            Port(1, "lo", "local", 1, 1_000_000_000, 1000, 1_000, 800),
            Port(2, "Gi0/0", "uplink", 1, 1_000_000_000, 1000, 12_500_000, 3_000_000),
            Port(3, "Gi0/1", "access", 1, 1_000_000_000, 1000, 500_000, 200_000),
            Port(4, "Gi0/2", "spare", 2, 100_000_000, 100, 0, 0)
        },
        Lldp = new[]
        {
            Neighbor(2, "sim-dist-01", "Gi0/1", "10.1.0.2"),
            Neighbor(3, "sim-access-01", "Gi0/1", "10.1.0.3")
        },
        Cdp = new[]
        {
            Neighbor(2, "sim-dist-01", "Gi0/1", "10.1.0.2")
        }
    };

    public static SimDevice Distribution { get; } = new()
    {
        SysName = "sim-dist-01",
        SysDescr = "NetSentinel Simulator, distribution switch",
        Location = "IDF-1",
        IncludeGauge = false,
        Ports = new[]
        {
            Port(1, "Gi0/1", "to-core", 1, 1_000_000_000, 1000, 3_000_000, 12_500_000),
            Port(2, "Gi0/2", "spare", 1, 1_000_000_000, 1000, 40_000, 20_000)
        },
        Lldp = new[] { Neighbor(1, "sim-core-01", "Gi0/0", "10.1.0.1") }
    };

    public static SimDevice Access { get; } = BuildAccess();

    private static SimDevice BuildAccess()
    {
        var ports = new List<SimPort>
        {
            Port(1, "Gi0/1", "uplink", 1, 1_000_000_000, 1000, 200_000, 500_000),
            Port(2, "Gi0/2", "printer", 2, 100_000_000, 100, 0, 0)
        };
        for (var number = 1; number <= 24; number++)
        {
            var adminDown = number is 23 or 24;
            var unplugged = number is 21 or 22;
            var oper = adminDown || unplugged ? 2 : 1;
            var alias = number switch
            {
                5 => "camera-lobby",
                >= 10 and <= 12 => $"desk-{number}",
                _ => ""
            };
            var live = oper == 1;
            ports.Add(Port(
                number + 2,
                $"Gi1/0/{number}",
                alias,
                oper,
                1_000_000_000,
                1000,
                live ? 8_000 + (number * 250) : 0,
                live ? 3_000 : 0,
                adminDown ? 2 : 1));
        }

        return new SimDevice
        {
            SysName = "sim-access-01",
            SysDescr = "NetSentinel Simulator, access switch",
            Location = "IDF-2",
            IncludeGauge = false,
            Ports = ports,
            Lldp = new[] { Neighbor(1, "sim-core-01", "Gi0/1", "10.1.0.1") }
        };
    }

    public static SimDevice DistributionDark { get; } = new()
    {
        SysName = "sim-dist-02",
        SysDescr = "NetSentinel Simulator, distribution switch, silent",
        Location = "IDF-1",
        IncludeGauge = false,
        Answers = false,
        Ports = new[]
        {
            Port(1, "Gi0/1", "to-core", 2, 1_000_000_000, 1000, 0, 0)
        }
    };

    public static SimDevice FirewallActive { get; } = new()
    {
        SysName = "sim-fw-01",
        SysDescr = "NetSentinel Simulator, Palo Alto firewall",
        Location = "FMC",
        IncludeGauge = false,
        IncludeSensors = true,
        HaState = "active",
        HaPeerState = "passive",
        Ports = new[]
        {
            Port(1, "ethernet1/1", "trust", 1, 1_000_000_000, 1000, 4_000_000, 1_500_000),
            Port(2, "ethernet1/2", "untrust", 1, 1_000_000_000, 1000, 1_500_000, 4_000_000)
        }
    };

    public static SimDevice FirewallPassive { get; } = new()
    {
        SysName = "sim-fw-02",
        SysDescr = "NetSentinel Simulator, Palo Alto firewall",
        Location = "FMC",
        IncludeGauge = false,
        HaState = "passive",
        HaPeerState = "active",
        Ports = new[]
        {
            Port(1, "ethernet1/1", "trust", 1, 1_000_000_000, 1000, 20_000, 12_000),
            Port(2, "ethernet1/2", "untrust", 2, 1_000_000_000, 1000, 0, 0)
        }
    };

    public static SimDevice Closet { get; } = new()
    {
        SysName = "sim-closet-01",
        SysDescr = "NetSentinel Simulator, closet switch, silent",
        Location = "Closet",
        IncludeGauge = false,
        Answers = false,
        Ports = new[]
        {
            Port(1, "Gi0/1", "uplink", 2, 1_000_000_000, 1000, 0, 0)
        }
    };

    public static IReadOnlyList<(int Port, SimDevice Device)> DefaultAgents { get; } = new (int, SimDevice)[]
    {
        (1161, Core),
        (1163, Distribution),
        (1165, DistributionDark),
        (1164, Access),
        (1166, Closet),
        (1167, FirewallActive),
        (1168, FirewallPassive)
    };

    private static SimPort Port(int index, string name, string alias, int oper, ulong speed, int highSpeed, double inbound, double outbound, int admin = 1) => new()
    {
        Index = index,
        Name = name,
        Alias = alias,
        Oper = oper,
        Admin = admin,
        SpeedBps = speed,
        HighSpeedMbps = highSpeed,
        InBytesPerSecond = inbound,
        OutBytesPerSecond = outbound
    };

    private static SimNeighbor Neighbor(int localPort, string remoteName, string remotePort, string address) => new()
    {
        LocalPort = localPort,
        RemoteName = remoteName,
        RemotePort = remotePort,
        RemoteAddress = address
    };
}
