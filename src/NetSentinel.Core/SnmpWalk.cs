namespace NetSentinel.Core;

/// <summary>
/// Pure walk rules: subtree bounds, row cap, time-limit truncation, type guess, and friendly names.
/// The SNMP client applies the same <see cref="Decide"/> result to every varbind it receives.
/// </summary>
public static class SnmpWalkLogic
{
    public const int DefaultMaxRows = 500;
    public const int MaxRowsLimit = 5000;
    public static readonly TimeSpan TimeLimit = TimeSpan.FromSeconds(20);

    public const string HrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2";
    public const string PanSessionUtilization = "1.3.6.1.4.1.25461.2.1.2.3.1";
    public const string EntPhysicalName = "1.3.6.1.2.1.47.1.1.1.1.7";
    public const string EntPhySensorType = "1.3.6.1.2.1.99.1.1.1.1";
    public const string EntPhySensorScale = "1.3.6.1.2.1.99.1.1.1.2";
    public const string EntPhySensorValue = "1.3.6.1.2.1.99.1.1.1.4";
    public const string CpmCpuEntry = "1.3.6.1.4.1.9.9.109.1.1.1.1";
    public const string EnvMonEntry = "1.3.6.1.4.1.9.9.13.1.3.1";
    public const string CiscoSensorEntry = "1.3.6.1.4.1.9.9.91.1.1.1.1";
    public const string MemoryEntry = "1.3.6.1.4.1.9.9.48.1.1.1";
    public const string SystemGroup = "1.3.6.1.2.1.1";
    public const string Mib2 = "1.3.6.1.2.1";

    public static int? NormalizeMaxRows(int? requested)
    {
        if (requested is null)
        {
            return DefaultMaxRows;
        }

        if (requested < 1)
        {
            return null;
        }

        return Math.Min(requested.Value, MaxRowsLimit);
    }

    public static string Normalize(string? text)
    {
        var oid = (text ?? "").Trim();
        if (oid.StartsWith('.'))
        {
            oid = oid[1..];
        }

        return oid;
    }

    public static bool IsOid(string? text)
    {
        var oid = Normalize(text);
        if (oid.Length is < 3 or > 200 || oid.EndsWith('.'))
        {
            return false;
        }

        var parts = oid.Split('.');
        if (parts.Length < 2 || parts[0] is not ("0" or "1" or "2"))
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length is 0 or > 10 || !part.All(char.IsDigit))
            {
                return false;
            }
        }

        return true;
    }

    public static bool WithinSubtree(string root, string oid)
    {
        root = Normalize(root);
        oid = Normalize(oid);
        return oid.Equals(root, StringComparison.Ordinal)
            || oid.StartsWith(root + ".", StringComparison.Ordinal);
    }

    public static int Compare(string left, string right)
    {
        var a = Normalize(left).Split('.');
        var b = Normalize(right).Split('.');
        var length = Math.Max(a.Length, b.Length);
        for (var i = 0; i < length; i++)
        {
            if (i >= a.Length)
            {
                return -1;
            }

            if (i >= b.Length)
            {
                return 1;
            }

            var av = ulong.TryParse(a[i], out var parsedA) ? parsedA : 0UL;
            var bv = ulong.TryParse(b[i], out var parsedB) ? parsedB : 0UL;
            if (av != bv)
            {
                return av < bv ? -1 : 1;
            }
        }

        return 0;
    }

    public static string? GuessKind(string? snmpType, bool numeric)
    {
        switch (snmpType)
        {
            case "Counter32":
            case "Counter64":
                return "counter";
            case "Integer32":
            case "Gauge32":
            case "Unsigned32":
            case "TimeTicks":
                return "gauge";
            case "OctetString" when numeric:
                return "gauge";
            default:
                return null;
        }
    }

    public static WalkStop Decide(string root, WalkProbe probe, int kept, int maxRows)
    {
        if (probe.Type is "EndOfMibView")
        {
            return WalkStop.End;
        }

        if (probe.Type is "NoSuchObject" or "NoSuchInstance")
        {
            return WalkStop.NoSuch;
        }

        if (!WithinSubtree(root, probe.Oid))
        {
            return WalkStop.End;
        }

        if (kept >= maxRows)
        {
            return WalkStop.RowCap;
        }

        return WalkStop.Keep;
    }

    /// <summary>
    /// Replays a walk in the order an agent would return it.
    /// <paramref name="timeAfterKept"/> simulates the overall deadline expiring once that many rows are kept
    /// and another in-subtree object is still waiting.
    /// </summary>
    public static WalkResult Collect(string root, IReadOnlyList<WalkProbe> probes, int maxRows, int? timeAfterKept = null)
    {
        root = Normalize(root);
        if (timeAfterKept == 0)
        {
            return Fail(root, maxRows, TimeoutText());
        }

        var rows = new List<WalkRow>();
        foreach (var probe in probes)
        {
            if (timeAfterKept is int expired && rows.Count >= expired && Decide(root, probe, rows.Count, maxRows) == WalkStop.Keep)
            {
                return Finish(root, rows, maxRows, truncated: true, limit: "time");
            }

            switch (Decide(root, probe, rows.Count, maxRows))
            {
                case WalkStop.Keep:
                    rows.Add(ToRow(probe));
                    break;
                case WalkStop.RowCap:
                    return Finish(root, rows, maxRows, truncated: true, limit: "rows");
                case WalkStop.NoSuch:
                    if (rows.Count == 0)
                    {
                        return Fail(root, maxRows, NoSuchText(probe.Type, string.IsNullOrEmpty(probe.Oid) ? root : probe.Oid));
                    }

                    return Finish(root, rows, maxRows, truncated: false, limit: null);
                default:
                    return Finish(root, rows, maxRows, truncated: false, limit: null);
            }
        }

        return Finish(root, rows, maxRows, truncated: false, limit: null);
    }

    public static string TimeoutText()
        => $"SNMP timed out before the walk finished. The limit is {TimeLimit.TotalSeconds:0} seconds per walk, and each request uses the device timeout.";

    public static string NoSuchText(string? type, string oid)
    {
        var name = type switch
        {
            "NoSuchObject" or "noSuchObject" => "noSuchObject",
            "NoSuchInstance" or "noSuchInstance" => "noSuchInstance",
            "NoSuchName" or "noSuchName" => "noSuchName",
            _ => string.IsNullOrWhiteSpace(type) ? "noSuchObject" : type
        };
        return $"The device returned {name} for {oid}. That OID is not implemented.";
    }

    public static string RowCapText(int count, int maxRows)
        => $"Stopped after {count} rows. The cap is {maxRows} (maximum {MaxRowsLimit}). Narrow the OID, or raise the cap.";

    public static string TimeText(int count)
        => $"Stopped after {TimeLimit.TotalSeconds:0} seconds with {count} rows. This result is partial.";

    public static string EmptyText(string oid)
        => $"No objects were returned under {oid}.";

    public static IReadOnlyList<string> CompanionOids(IEnumerable<string> walked)
    {
        var have = new HashSet<string>(walked.Select(Normalize), StringComparer.Ordinal);
        var want = new List<string>();
        void Need(string oid)
        {
            oid = Normalize(oid);
            if (oid.Length == 0 || have.Contains(oid) || want.Contains(oid, StringComparer.Ordinal))
            {
                return;
            }

            want.Add(oid);
        }

        foreach (var oid in have)
        {
            if (TryIndex(oid, EntPhySensorValue, out var index))
            {
                Need(EntPhysicalName + "." + index);
                Need(EntPhySensorType + "." + index);
                Need(EntPhySensorScale + "." + index);
            }

            if (TryColumn(oid, CiscoSensorEntry, out var column, out index) && column == 4)
            {
                Need(EntPhysicalName + "." + index);
                Need(CiscoSensorEntry + ".1." + index);
                Need(CiscoSensorEntry + ".2." + index);
            }

            if (TryColumn(oid, EnvMonEntry, out column, out index) && column == 3)
            {
                Need(EnvMonEntry + ".2." + index);
            }

            if (TryColumn(oid, MemoryEntry, out column, out index) && column is 5 or 6 or 7)
            {
                Need(MemoryEntry + ".2." + index);
            }

            if (want.Count >= 1500)
            {
                break;
            }
        }

        return want;
    }

    public static void ApplyLabels(IList<WalkRow> rows, IReadOnlyDictionary<string, string>? extras = null)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            values[Normalize(row.Oid)] = row.Value ?? "";
        }

        if (extras is not null)
        {
            foreach (var pair in extras)
            {
                values[Normalize(pair.Key)] = pair.Value ?? "";
            }
        }

        foreach (var row in rows)
        {
            if (string.IsNullOrEmpty(row.Kind))
            {
                row.Kind = GuessKind(row.Type, row.Numeric);
            }

            Annotate(row, Normalize(row.Oid), values);
        }
    }

    public static bool TryIndex(string oid, string columnPrefix, out string index)
    {
        var prefix = Normalize(columnPrefix) + ".";
        var text = Normalize(oid);
        if (!text.StartsWith(prefix, StringComparison.Ordinal))
        {
            index = "";
            return false;
        }

        index = text[prefix.Length..];
        return index.Length > 0 && index.All(ch => char.IsDigit(ch) || ch == '.');
    }

    public static bool TryColumn(string oid, string entry, out int column, out string index)
    {
        column = 0;
        index = "";
        if (!TryIndex(oid, entry, out var rest))
        {
            return false;
        }

        var dot = rest.IndexOf('.');
        if (dot <= 0)
        {
            return false;
        }

        if (!int.TryParse(rest[..dot], out column))
        {
            return false;
        }

        index = rest[(dot + 1)..];
        return index.Length > 0;
    }

    public static string SuggestName(string? label, string? metric)
    {
        var name = Collapse(label);
        var metricText = Collapse(metric);
        if (name.Length == 0)
        {
            return TrimName(metricText);
        }

        if (metricText.Length == 0 || name.Contains(metricText, StringComparison.OrdinalIgnoreCase))
        {
            return TrimName(name);
        }

        if (metricText.Contains("temp", StringComparison.OrdinalIgnoreCase)
            && name.Contains("temp", StringComparison.OrdinalIgnoreCase))
        {
            return TrimName(name);
        }

        return TrimName(name + " " + metricText);
    }

    private static void Annotate(WalkRow row, string oid, Dictionary<string, string> values)
    {
        if (TryIndex(oid, HrProcessorLoad, out var index))
        {
            row.Label = index switch
            {
                "1" => "Management plane",
                "2" => "Data plane",
                _ => "Processor " + index
            };
            row.SuggestedName = SuggestName(row.Label, "CPU");
            row.Unit ??= "%";
            return;
        }

        if (WithinSubtree(PanSessionUtilization, oid))
        {
            row.Label = "Session utilization";
            row.SuggestedName = "Session utilization";
            row.Unit ??= "%";
            return;
        }

        if (TryIndex(oid, EntPhySensorValue, out index))
        {
            ApplySensor(row, index, values, EntPhySensorType, EntPhySensorScale);
            return;
        }

        if (TryColumn(oid, CiscoSensorEntry, out var column, out index) && column == 4)
        {
            ApplySensor(row, index, values, CiscoSensorEntry + ".1", CiscoSensorEntry + ".2");
            return;
        }

        if (TryColumn(oid, EnvMonEntry, out column, out index))
        {
            if (column == 2)
            {
                row.Label = Collapse(row.Value);
                row.SuggestedName = SuggestName(row.Label, "description");
                return;
            }

            if (column == 3)
            {
                var descr = Lookup(values, EnvMonEntry + ".2." + index);
                row.Label = string.IsNullOrEmpty(descr) ? null : descr;
                row.SensorType = "celsius";
                row.SuggestedName = string.IsNullOrEmpty(descr) ? "Temperature " + index : SuggestName(descr, "temperature");
                row.Unit ??= "C";
                return;
            }
        }

        if (TryColumn(oid, CpmCpuEntry, out column, out index))
        {
            var metric = column switch
            {
                3 or 6 => "CPU 5sec",
                4 or 7 => "CPU 1min",
                5 or 8 => "CPU 5min",
                _ => null
            };
            if (metric is not null)
            {
                row.Label = metric;
                row.SuggestedName = index == "1" ? metric : TrimName(metric + " " + index);
                row.Unit ??= "%";
                return;
            }
        }

        if (TryColumn(oid, MemoryEntry, out column, out index))
        {
            if (column == 2)
            {
                row.Label = Collapse(row.Value);
                row.SuggestedName = string.IsNullOrEmpty(row.Label) ? "Memory pool " + index : TrimName(row.Label);
                return;
            }

            var metric = column switch
            {
                5 => "used",
                6 => "free",
                7 => "largest free",
                _ => null
            };
            if (metric is not null)
            {
                var pool = Lookup(values, MemoryEntry + ".2." + index);
                row.Label = string.IsNullOrEmpty(pool) ? null : pool;
                row.SuggestedName = string.IsNullOrEmpty(pool) ? "Memory " + metric : SuggestName(pool, metric);
                return;
            }
        }

        if (TryColumn(oid, SystemGroup, out column, out index) && index == "0")
        {
            var name = column switch
            {
                1 => "sysDescr",
                2 => "sysObjectID",
                3 => "sysUpTime",
                4 => "sysContact",
                5 => "sysName",
                6 => "sysLocation",
                7 => "sysServices",
                _ => null
            };
            if (name is not null)
            {
                row.Label = name;
                row.SuggestedName = name;
            }
        }
    }

    private static void ApplySensor(WalkRow row, string index, Dictionary<string, string> values, string typePrefix, string scalePrefix)
    {
        var name = Lookup(values, EntPhysicalName + "." + index);
        var type = SensorTypeName(Lookup(values, typePrefix + "." + index));
        var scale = SensorScaleName(Lookup(values, scalePrefix + "." + index));
        row.Label = string.IsNullOrEmpty(name) ? null : name;
        row.SensorType = type;
        row.Scale = scale;
        var metric = type switch
        {
            "celsius" => "temperature",
            "percentRH" => "humidity",
            "voltsAC" or "voltsDC" => "voltage",
            "amperes" => "current",
            "watts" => "power",
            "rpm" => "fan",
            _ => null
        };
        if (!string.IsNullOrEmpty(name))
        {
            row.SuggestedName = SuggestName(name, metric);
        }
        else if (type == "celsius")
        {
            row.SuggestedName = "Temperature " + index;
        }
        else if (metric is not null)
        {
            row.SuggestedName = TrimName(char.ToUpperInvariant(metric[0]) + metric[1..] + " " + index);
        }
        else
        {
            row.SuggestedName = "Sensor " + index;
        }

        row.Unit ??= type switch
        {
            "celsius" when scale is null or "units" => "C",
            "celsius" when scale == "milli" => "mC",
            "percentRH" => "%",
            _ => null
        };
    }

    private static string? SensorTypeName(string? raw)
    {
        if (!int.TryParse(raw, out var code))
        {
            return null;
        }

        return code switch
        {
            1 => "other",
            2 => "unknown",
            3 => "voltsAC",
            4 => "voltsDC",
            5 => "amperes",
            6 => "watts",
            7 => "hertz",
            8 => "celsius",
            9 => "percentRH",
            10 => "rpm",
            11 => "cmm",
            12 => "truthvalue",
            13 => "specialEnum",
            14 => "dBm",
            _ => "type " + code
        };
    }

    private static string? SensorScaleName(string? raw)
    {
        if (!int.TryParse(raw, out var code))
        {
            return null;
        }

        return code switch
        {
            1 => "yocto",
            2 => "zepto",
            3 => "atto",
            4 => "femto",
            5 => "pico",
            6 => "nano",
            7 => "micro",
            8 => "milli",
            9 => "units",
            10 => "kilo",
            11 => "mega",
            12 => "giga",
            13 => "tera",
            14 => "exa",
            15 => "peta",
            16 => "zetta",
            17 => "yotta",
            _ => "scale " + code
        };
    }

    private static string Lookup(Dictionary<string, string> values, string oid)
        => values.TryGetValue(Normalize(oid), out var value) ? Collapse(value) : "";

    private static WalkRow ToRow(WalkProbe probe) => new()
    {
        Oid = Normalize(probe.Oid),
        Type = probe.Type,
        Value = probe.Value,
        Numeric = probe.Numeric,
        Kind = GuessKind(probe.Type, probe.Numeric)
    };

    private static WalkResult Finish(string root, List<WalkRow> rows, int maxRows, bool truncated, string? limit)
    {
        string? message = null;
        if (truncated && limit == "rows")
        {
            message = RowCapText(rows.Count, maxRows);
        }
        else if (truncated && limit == "time")
        {
            message = TimeText(rows.Count);
        }
        else if (rows.Count == 0)
        {
            message = EmptyText(root);
        }

        return new WalkResult
        {
            Ok = true,
            BaseOid = root,
            Truncated = truncated,
            Limit = limit,
            Message = message,
            MaxRows = maxRows,
            Rows = rows
        };
    }

    private static WalkResult Fail(string root, int maxRows, string error) => new()
    {
        Ok = false,
        Error = error,
        BaseOid = root,
        MaxRows = maxRows,
        Rows = new List<WalkRow>()
    };

    private static string Collapse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }

        return string.Join(' ', text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }

    private static string TrimName(string text)
    {
        text = Collapse(text);
        return text.Length <= 80 ? text : text[..80].TrimEnd();
    }
}

public enum WalkStop
{
    Keep,
    End,
    RowCap,
    NoSuch
}

public sealed record WalkProbe(string Oid, string Type, string Value, bool Numeric);

public sealed class WalkRow
{
    public string Oid { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public bool Numeric { get; set; }
    public string? Kind { get; set; }
    public string? Label { get; set; }
    public string? SensorType { get; set; }
    public string? Scale { get; set; }
    public string? SuggestedName { get; set; }
    public string? Unit { get; set; }
}

public sealed class WalkResult
{
    public bool Ok { get; init; } = true;
    public string? Error { get; init; }
    public string BaseOid { get; init; } = "";
    public bool Truncated { get; init; }
    public string? Limit { get; init; }
    public string? Message { get; init; }
    public int MaxRows { get; init; }
    public List<WalkRow> Rows { get; init; } = new();
}

public sealed record WalkPreset(string Id, string Label, string Oid, string? Hint, bool Large);

public static class WalkPresets
{
    public static readonly IReadOnlyList<WalkPreset> All = new WalkPreset[]
    {
        new("pa-cpu", "Palo Alto CPU (hrProcessorLoad)", SnmpWalkLogic.HrProcessorLoad, ".1 is the management plane, .2 the data plane.", false),
        new("pa-session", "Palo Alto session utilization", SnmpWalkLogic.PanSessionUtilization, null, false),
        new("entity-sensor", "ENTITY-SENSOR-MIB values", SnmpWalkLogic.EntPhySensorValue, "Palo Alto temperatures and other entity sensors. Names come from entPhysicalName.", false),
        new("cisco-cpu", "Cisco CPU (cpmCPUTotal)", SnmpWalkLogic.CpmCpuEntry, ".7 is 1-minute, .8 is 5-minute.", false),
        new("cisco-envmon", "Cisco ENVMON temperature", SnmpWalkLogic.EnvMonEntry, ".2 is the description, .3 the value.", false),
        new("cisco-entity-sensor", "Cisco entSensorValue", SnmpWalkLogic.CiscoSensorEntry + ".4", "Type is column .1 (8 is celsius) and scale is column .2.", false),
        new("cisco-memory", "Cisco memory pool", SnmpWalkLogic.MemoryEntry, null, false),
        new("system", "system", SnmpWalkLogic.SystemGroup, null, false),
        new("mib-2", "Full MIB-2", SnmpWalkLogic.Mib2, "This tree is large. The walk stops at the row cap or the time limit.", true)
    };
}
