using NetSentinel.Core;

namespace NetSentinel.Tests;

public class SnmpWalkTests
{
    [Fact]
    public void Walk_stops_at_the_end_of_the_subtree()
    {
        var probes = new[]
        {
            Probe("1.3.6.1.2.1.1.1.0", "OctetString", "descr"),
            Probe("1.3.6.1.2.1.1.5.0", "OctetString", "core"),
            Probe("1.3.6.1.2.1.2.1.0", "Integer32", "4", numeric: true),
            Probe("1.3.6.1.2.1.1.6.0", "OctetString", "should-not-be-read")
        };

        var result = SnmpWalkLogic.Collect("1.3.6.1.2.1.1", probes, maxRows: 50);

        Assert.True(result.Ok);
        Assert.False(result.Truncated);
        Assert.Equal(new[] { "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0" }, result.Rows.Select(row => row.Oid));
        Assert.False(SnmpWalkLogic.WithinSubtree("1.3.6.1.2.1.1", "1.3.6.1.2.1.10.0"));
        Assert.True(SnmpWalkLogic.WithinSubtree(".1.3.6.1.2.1.1", "1.3.6.1.2.1.1.5.0"));
    }

    [Fact]
    public void Walk_stops_at_the_row_cap_and_says_it_was_truncated()
    {
        var probes = Enumerable.Range(1, 6)
            .Select(index => Probe($"1.3.6.1.2.1.1.{index}.0", "OctetString", "v" + index))
            .ToArray();

        var capped = SnmpWalkLogic.Collect("1.3.6.1.2.1.1", probes, maxRows: 3);
        Assert.Equal(3, capped.Rows.Count);
        Assert.True(capped.Truncated);
        Assert.Equal("rows", capped.Limit);
        Assert.Contains("cap is 3", capped.Message);

        var exact = SnmpWalkLogic.Collect("1.3.6.1.2.1.1", probes.Take(2).Append(Probe("1.3.6.1.2.1.2.1.0", "Integer32", "1", true)).ToArray(), maxRows: 2);
        Assert.Equal(2, exact.Rows.Count);
        Assert.False(exact.Truncated);

        var timed = SnmpWalkLogic.Collect("1.3.6.1.2.1.1", probes, maxRows: 50, timeAfterKept: 2);
        Assert.Equal(2, timed.Rows.Count);
        Assert.True(timed.Truncated);
        Assert.Equal("time", timed.Limit);
        Assert.Contains("partial", timed.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NoSuchObject_is_an_error_and_not_a_row()
    {
        var result = SnmpWalkLogic.Collect(
            "1.3.6.1.4.1.9.9.13",
            new[] { new WalkProbe("1.3.6.1.4.1.9.9.13", "NoSuchObject", "noSuchObject", false) },
            maxRows: 50);

        Assert.False(result.Ok);
        Assert.Empty(result.Rows);
        Assert.Contains("noSuchObject", result.Error);
        Assert.Contains("not implemented", result.Error);
    }

    [Fact]
    public void Type_guess_is_gauge_for_integers_and_counter_for_counters()
    {
        Assert.Equal("counter", SnmpWalkLogic.GuessKind("Counter32", numeric: true));
        Assert.Equal("counter", SnmpWalkLogic.GuessKind("Counter64", numeric: true));
        Assert.Equal("gauge", SnmpWalkLogic.GuessKind("Integer32", numeric: true));
        Assert.Equal("gauge", SnmpWalkLogic.GuessKind("Gauge32", numeric: true));
        Assert.Equal("gauge", SnmpWalkLogic.GuessKind("OctetString", numeric: true));
        Assert.Null(SnmpWalkLogic.GuessKind("OctetString", numeric: false));

        var rows = new List<WalkRow>
        {
            new() { Oid = "1.3.6.1.2.1.99.1.1.1.4.1", Type = "Integer32", Value = "36", Numeric = true },
            new() { Oid = "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", Type = "Gauge32", Value = "4", Numeric = true },
            new() { Oid = "1.3.6.1.4.1.9.9.13.1.3.1.2.1", Type = "OctetString", Value = "Inlet Temp", Numeric = false },
            new() { Oid = "1.3.6.1.4.1.9.9.13.1.3.1.3.1", Type = "Gauge32", Value = "41", Numeric = true },
            new() { Oid = "1.3.6.1.2.1.2.2.1.10.1", Type = "Counter32", Value = "100", Numeric = true },
            new() { Oid = "1.3.6.1.2.1.25.3.3.1.2.2", Type = "Integer32", Value = "24", Numeric = true }
        };
        SnmpWalkLogic.ApplyLabels(rows, new Dictionary<string, string>
        {
            ["1.3.6.1.2.1.47.1.1.1.1.7.1"] = "Inlet Temp",
            ["1.3.6.1.2.1.99.1.1.1.1.1"] = "8",
            ["1.3.6.1.2.1.99.1.1.1.2.1"] = "9"
        });

        var sensor = rows[0];
        Assert.Equal("gauge", sensor.Kind);
        Assert.Equal("Inlet Temp", sensor.Label);
        Assert.Equal("celsius", sensor.SensorType);
        Assert.Equal("units", sensor.Scale);
        Assert.Equal("Inlet Temp", sensor.SuggestedName);
        Assert.Equal("C", sensor.Unit);

        Assert.Equal("CPU 5min", rows[1].SuggestedName);
        Assert.Equal("gauge", rows[1].Kind);
        Assert.Equal("Inlet Temp", rows[3].Label);
        Assert.Equal("Inlet Temp", rows[3].SuggestedName);
        Assert.Equal("counter", rows[4].Kind);
        Assert.Equal("Data plane CPU", rows[5].SuggestedName);
    }

    [Fact]
    public void Presets_cover_the_palo_alto_and_cisco_trees()
    {
        string[] oids =
        {
            "1.3.6.1.2.1.25.3.3.1.2",
            "1.3.6.1.4.1.25461.2.1.2.3.1",
            "1.3.6.1.2.1.99.1.1.1.4",
            "1.3.6.1.4.1.9.9.109.1.1.1.1",
            "1.3.6.1.4.1.9.9.13.1.3.1",
            "1.3.6.1.4.1.9.9.91.1.1.1.1.4",
            "1.3.6.1.4.1.9.9.48.1.1.1",
            "1.3.6.1.2.1.1",
            "1.3.6.1.2.1"
        };

        foreach (var oid in oids)
        {
            Assert.Contains(WalkPresets.All, preset => preset.Oid == oid);
        }

        Assert.Contains(WalkPresets.All, preset => preset.Oid == "1.3.6.1.2.1" && preset.Large);
        Assert.Equal(500, SnmpWalkLogic.NormalizeMaxRows(null));
        Assert.Equal(5000, SnmpWalkLogic.NormalizeMaxRows(9000));
        Assert.Null(SnmpWalkLogic.NormalizeMaxRows(0));
    }

    private static WalkProbe Probe(string oid, string type, string value, bool numeric = false)
        => new(oid, type, value, numeric);
}