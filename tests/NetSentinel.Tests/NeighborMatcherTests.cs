using NetSentinel.Core;

namespace NetSentinel.Tests;

public class NeighborMatcherTests
{
    private static readonly KnownDevice[] Devices =
    {
        new(1, "Loopback simulator", "10.1.0.1", "sim-core-01"),
        new(2, "Distribution", "10.1.0.2", "sim-dist-01"),
        new(3, "Access closet", "10.1.0.3", null),
        new(4, "Twin", "10.1.0.1", "other-core")
    };

    private static readonly KnownInterface[] Interfaces =
    {
        new(2, "Gi0/0", "Gi0/0", "uplink", 10, 2.4),
        new(3, "Gi0/1", "Gi0/1", "access", 0.4, 0.2)
    };

    [Fact]
    public void Lldp_rows_parse_sysname_port_and_local_port()
    {
        var rows = new[]
        {
            new SnmpBinding("1.0.8802.1.1.2.1.4.1.1.5.0.2.1", "aa:bb"),
            new SnmpBinding("1.0.8802.1.1.2.1.4.1.1.7.0.2.1", "Gi0/1"),
            new SnmpBinding("1.0.8802.1.1.2.1.4.1.1.9.0.2.1", "sim-dist-01"),
            new SnmpBinding("1.0.8802.1.1.2.1.3.7.1.3.2", "Gi0/0")
        };
        var neighbor = Assert.Single(NeighborTables.Parse(rows));
        Assert.Equal("lldp", neighbor.Protocol);
        Assert.Equal("sim-dist-01", neighbor.RemoteName);
        Assert.Equal("Gi0/1", neighbor.RemotePort);
        Assert.Equal("Gi0/0", neighbor.LocalPort);
        Assert.Equal(2, neighbor.LocalPortNum);
    }

    [Fact]
    public void Cdp_rows_parse_device_id_and_ifindex()
    {
        var rows = new[]
        {
            new SnmpBinding("1.3.6.1.4.1.9.9.23.1.2.1.1.4.3.1", "10.1.0.3"),
            new SnmpBinding("1.3.6.1.4.1.9.9.23.1.2.1.1.6.3.1", "sim-access-01.lab"),
            new SnmpBinding("1.3.6.1.4.1.9.9.23.1.2.1.1.7.3.1", "Gi0/1")
        };
        var neighbor = Assert.Single(NeighborTables.Parse(rows));
        Assert.Equal("cdp", neighbor.Protocol);
        Assert.Equal("sim-access-01.lab", neighbor.RemoteName);
        Assert.Equal("10.1.0.3", neighbor.RemoteAddress);
        Assert.Equal(3, neighbor.LocalPortNum);
    }

    [Fact]
    public void Sysname_match_beats_a_shared_address()
    {
        var neighbor = new NeighborObservation("lldp", "sim-dist-01", "sim-dist-01", "10.1.0.1", "Gi0/1", "Gi0/0", 2);
        var match = Assert.Single(NeighborMatcher.Match(1, new[] { neighbor }, Devices, Interfaces));
        Assert.Equal(2, match.RemoteDeviceId);
        Assert.Equal(2, match.LocalIfIndex);
        Assert.Equal(10, match.Utilization);
        Assert.Equal("Gi0/0", match.LocalPort);
    }

    [Fact]
    public void Short_hostname_and_management_address_match()
    {
        var byName = NeighborMatcher.FindDevice(1, new NeighborObservation("cdp", "sim-dist-01.lab", null, null, null, null, null), Devices);
        Assert.Equal(2, byName!.Id);

        var byAddress = NeighborMatcher.FindDevice(1, new NeighborObservation("cdp", null, null, "10.1.0.3", "Gi0/1", null, 3), Devices);
        Assert.Equal(3, byAddress!.Id);
    }

    [Fact]
    public void Unknown_neighbors_and_self_are_not_linked()
    {
        var neighbors = new[]
        {
            new NeighborObservation("lldp", "stranger", null, "10.9.9.9", null, null, null),
            new NeighborObservation("lldp", "sim-core-01", null, null, null, null, null)
        };
        Assert.Empty(NeighborMatcher.Match(1, neighbors, Devices, Interfaces));
    }

    [Fact]
    public void Ambiguous_address_does_not_guess()
    {
        var neighbor = new NeighborObservation("lldp", null, null, "10.1.0.1", null, null, null);
        Assert.Null(NeighborMatcher.FindDevice(2, neighbor, Devices));
    }
}
