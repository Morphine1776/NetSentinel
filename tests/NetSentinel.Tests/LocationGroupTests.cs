using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Services;

namespace NetSentinel.Tests;

public class LocationGroupTests
{
    [Fact]
    public void Groups_trim_and_ignore_case_and_blank_locations_are_unassigned()
    {
        var groups = LocationGroups.Group(new[]
        {
            Device(2, "edge", "  idf-1 "),
            Device(1, "core", "IDF-1"),
            Device(3, "spare", "   "),
            Device(4, "other", null)
        });

        var idf = Assert.Single(groups, group => group.Key == "IDF-1");
        Assert.Equal("IDF-1", idf.Name);
        Assert.Equal(new[] { 1, 2 }, idf.DeviceIds);

        var unassigned = Assert.Single(groups, group => group.Key == "");
        Assert.Equal("Unassigned", unassigned.Name);
        Assert.Equal(new[] { 4, 3 }, unassigned.DeviceIds);
    }

    [Fact]
    public void Display_name_prefers_the_most_common_spelling()
    {
        var groups = LocationGroups.Group(new[]
        {
            Device(1, "a", "mdf"),
            Device(2, "b", "MDF"),
            Device(3, "c", "MDF")
        });

        var group = Assert.Single(groups);
        Assert.Equal("MDF", group.Name);
        Assert.Equal("MDF", group.Key);
    }

    [Fact]
    public void Tied_spellings_pick_a_stable_ordinal_name()
    {
        var forward = LocationGroups.Group(new[] { Device(1, "a", "lab"), Device(2, "b", "Lab") });
        var reverse = LocationGroups.Group(new[] { Device(2, "b", "Lab"), Device(1, "a", "lab") });
        Assert.Equal("Lab", Assert.Single(forward).Name);
        Assert.Equal(forward[0].Name, reverse[0].Name);
    }

    [Fact]
    public void All_reporting_is_healthy()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "MDF", DevicePresence.Reporting),
            Device(2, "b", "MDF", DevicePresence.Reporting)
        }));

        Assert.Equal(LocationHealth.Healthy, group.Health);
        Assert.Equal("All reporting", group.Cue);
        Assert.Equal(2, group.Reporting);
        Assert.Equal(0, group.Down);
        Assert.Equal("2/2", $"{group.Reporting}/{group.Total}");
    }

    [Fact]
    public void Some_down_is_degraded()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "IDF-1", DevicePresence.Reporting),
            Device(2, "b", "IDF-1", DevicePresence.Down),
            Device(3, "c", "IDF-1", DevicePresence.Pending)
        }));

        Assert.Equal(LocationHealth.Degraded, group.Health);
        Assert.Equal("Some down", group.Cue);
        Assert.Equal(1, group.Reporting);
        Assert.Equal(1, group.Down);
        Assert.Equal(1, group.Pending);
        Assert.Equal(3, group.Total);
    }

    [Fact]
    public void All_down_is_critical_even_without_an_alert()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "Closet", DevicePresence.Down),
            Device(2, "b", "Closet", DevicePresence.Down)
        }));

        Assert.Equal(LocationHealth.Critical, group.Health);
        Assert.Equal("All down", group.Cue);
        Assert.False(group.OpenCritical);
    }

    [Fact]
    public void Open_critical_alert_is_red_when_every_device_is_reporting()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "IDF-2", DevicePresence.Reporting),
            Device(2, "b", "IDF-2", DevicePresence.Reporting, critical: true)
        }));

        Assert.Equal(LocationHealth.Critical, group.Health);
        Assert.Equal("Critical alert", group.Cue);
        Assert.True(group.OpenCritical);
        Assert.Equal(2, group.Reporting);
    }

    [Fact]
    public void Critical_alert_outranks_a_partial_outage()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "Lab", DevicePresence.Reporting, critical: true),
            Device(2, "b", "Lab", DevicePresence.Down)
        }));

        Assert.Equal(LocationHealth.Critical, group.Health);
        Assert.Equal("Critical alert", group.Cue);
    }

    [Fact]
    public void Pending_and_paused_without_downs_are_waiting()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "a", "Dock", DevicePresence.Pending),
            Device(2, "b", "Dock", DevicePresence.Paused),
            Device(3, "c", "Dock", DevicePresence.Reporting)
        }));

        Assert.Equal(LocationHealth.Waiting, group.Health);
        Assert.Equal("Waiting", group.Cue);
        Assert.Equal(1, group.Paused);
    }

    [Fact]
    public void A_single_down_device_is_all_down()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(1, "closet", "Closet", DevicePresence.Down)
        }));

        Assert.Equal(LocationHealth.Critical, group.Health);
        Assert.Equal("All down", group.Cue);
    }

    [Fact]
    public void Problems_sort_ahead_of_healthy_groups_then_alphabetically()
    {
        var groups = LocationGroups.Group(new[]
        {
            Device(1, "h", "MDF", DevicePresence.Reporting),
            Device(2, "z1", "Zoo", DevicePresence.Down),
            Device(3, "a1", "Annex", DevicePresence.Down),
            Device(4, "m1", "mid", DevicePresence.Reporting),
            Device(5, "m2", "mid", DevicePresence.Down),
            Device(6, "w", "Wait", DevicePresence.Pending)
        });

        Assert.Equal(new[] { "Annex", "Zoo", "mid", "Wait", "MDF" }, groups.Select(group => group.Name).ToArray());
        Assert.Equal(LocationHealth.Critical, groups[0].Health);
        Assert.Equal(LocationHealth.Critical, groups[1].Health);
        Assert.Equal(LocationHealth.Degraded, groups[2].Health);
        Assert.Equal(LocationHealth.Waiting, groups[3].Health);
        Assert.Equal(LocationHealth.Healthy, groups[4].Health);
    }

    [Fact]
    public void Devices_inside_a_group_are_ordered_by_name()
    {
        var group = Assert.Single(LocationGroups.Group(new[]
        {
            Device(3, "core", "MDF"),
            Device(1, "Access", "MDF"),
            Device(2, "access-2", "MDF")
        }));

        Assert.Equal(new[] { 1, 2, 3 }, group.DeviceIds);
    }

    [Theory]
    [InlineData(false, true, true, DevicePresence.Paused)]
    [InlineData(true, false, false, DevicePresence.Pending)]
    [InlineData(true, true, true, DevicePresence.Reporting)]
    [InlineData(true, true, false, DevicePresence.Down)]
    public void Presence_follows_enabled_poll_and_snmp(bool enabled, bool polled, bool snmpOk, DevicePresence expected)
    {
        Assert.Equal(expected, LocationGroups.Presence(enabled, polled, snmpOk));
    }

    [Fact]
    public void Board_marks_a_location_critical_when_a_device_has_an_open_critical_alert()
    {
        var now = DateTime.UtcNow;
        var devices = new List<Device>
        {
            Polled(1, "sim-core-01", "MDF", snmpOk: true, now),
            Polled(2, "sim-access-01", "idf-2", snmpOk: true, now)
        };

        var board = DeviceBoardBuilder.Build(devices, new HashSet<int> { 2 });
        var group = Assert.Single(board.Groups, item => item.Key == "IDF-2");

        Assert.Equal("critical", group.Health);
        Assert.Equal("Critical alert", group.Cue);
        Assert.Equal("IDF-2", group.Key);
        Assert.Equal("idf-2", group.Name);
        Assert.Equal(1, group.Reporting);
        Assert.Equal("Up", Assert.Single(group.Devices).Status);
        Assert.Equal(2, board.Reachable);
        Assert.Equal(0, board.Down);
    }

    [Fact]
    public void Board_counts_match_the_previous_overview()
    {
        var now = DateTime.UtcNow;
        var devices = new List<Device>
        {
            Polled(1, "up", "MDF", snmpOk: true, now),
            Polled(2, "degraded", "MDF", snmpOk: true, now, pingOk: false),
            Polled(3, "down", "IDF-1", snmpOk: false, now, error: "timeout"),
            new() { Id = 4, Name = "pending", Host = "10.0.0.4", Location = "", Enabled = true, Port = 161 },
            new() { Id = 5, Name = "paused", Host = "10.0.0.5", Location = "MDF", Enabled = false, Port = 161, LastPollAt = now, LastSnmpOk = true }
        };

        var board = DeviceBoardBuilder.Build(devices, new HashSet<int>());

        Assert.Equal(2, board.Reachable);
        Assert.Equal(1, board.Down);
        Assert.Equal(2, board.Waiting);
        Assert.Equal(5, board.Watched);

        var mdf = Assert.Single(board.Groups, group => group.Name == "MDF");
        Assert.Equal("waiting", mdf.Health);
        Assert.Equal(2, mdf.Reporting);
        Assert.Equal(1, mdf.Paused);
        var down = Assert.Single(board.Groups, group => group.Name == "IDF-1");
        Assert.Equal("critical", down.Health);
        Assert.Equal("All down", down.Cue);
        Assert.Equal("timeout", Assert.Single(down.Devices).LastError);
        Assert.Equal("Unassigned", board.Groups.Single(group => group.Key == "").Name);
    }

    private static LocationDeviceInput Device(int id, string name, string? location, DevicePresence presence = DevicePresence.Reporting, bool critical = false)
        => new(id, name, "10.0.0." + id, location, presence, critical);

    private static Device Polled(int id, string name, string location, bool snmpOk, DateTime polled, bool? pingOk = true, string? error = null) => new()
    {
        Id = id,
        Name = name,
        Host = "10.0.0." + id,
        Port = 161,
        Location = location,
        Enabled = true,
        LastPollAt = polled,
        LastSnmpOk = snmpOk,
        LastPingOk = pingOk,
        LastResponseMs = snmpOk ? 12 : null,
        LastSysName = name,
        LastSysUpTimeTicks = snmpOk ? 12_000 : null,
        LastError = error,
        PollIntervalSeconds = 60
    };
}
