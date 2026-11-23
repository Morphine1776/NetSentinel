namespace NetSentinel.Core;

public enum AlertSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2
}

public enum AlertKind
{
    DeviceDown = 0,
    DeviceUp = 1,
    DeviceReboot = 2,
    InterfaceDown = 3,
    InterfaceUp = 4,
    Threshold = 5
}

public enum ThresholdOperator
{
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual
}

public enum AlertTransitionType
{
    Open,
    Resolve
}

public sealed record AlertRuleModel(
    int Id,
    string Name,
    string Metric,
    string? InterfaceFilter,
    ThresholdOperator Operator,
    double Threshold,
    AlertSeverity Severity);

public sealed record InterfaceSnapshot(
    int IfIndex,
    string Descr,
    string? Name,
    int AdminStatus,
    int OperStatus,
    double? InBps,
    double? OutBps,
    double? InUtil,
    double? OutUtil);

public sealed record CustomSnapshot(
    int CustomOidId,
    string Name,
    double? NumericValue,
    double? RatePerSecond);

public sealed record PollSnapshot(
    bool SnmpOk,
    bool? PingOk,
    int? ResponseMs,
    long? SysUpTimeTicks,
    IReadOnlyList<InterfaceSnapshot> Interfaces,
    IReadOnlyList<CustomSnapshot> Customs);

public sealed record AlertTransition(
    AlertTransitionType Type,
    string DedupKey,
    AlertKind Kind,
    AlertSeverity Severity,
    string Message,
    int? IfIndex,
    int? RuleId);

public static class AlertEvaluator
{
    public static List<AlertTransition> Evaluate(
        string scope,
        string deviceName,
        PollSnapshot? previous,
        PollSnapshot current,
        int consecutiveSnmpFailures,
        int failureThreshold,
        IReadOnlyList<AlertRuleModel> rules,
        IReadOnlySet<string> openKeys)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(openKeys);

        if (failureThreshold < 1)
        {
            failureThreshold = 1;
        }

        var transitions = new List<AlertTransition>();
        var fired = new HashSet<string>(StringComparer.Ordinal);
        var downKey = $"{scope}:down";

        if (!current.SnmpOk)
        {
            if (consecutiveSnmpFailures >= failureThreshold && !openKeys.Contains(downKey))
            {
                var pingNote = current.PingOk switch
                {
                    true => " Host answers ping.",
                    false => " Ping failed as well.",
                    _ => ""
                };
                transitions.Add(Open(
                    downKey,
                    AlertKind.DeviceDown,
                    AlertSeverity.Critical,
                    $"Device {deviceName} is unreachable. SNMP did not respond.{pingNote}",
                    null,
                    null));
            }
        }
        else if (openKeys.Contains(downKey))
        {
            transitions.Add(Resolve(
                downKey,
                AlertKind.DeviceDown,
                AlertSeverity.Critical,
                $"Device {deviceName} is reachable again.",
                null,
                null));
            transitions.Add(Open(
                $"{scope}:up:{current.SysUpTimeTicks?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "na"}",
                AlertKind.DeviceUp,
                AlertSeverity.Info,
                $"Device {deviceName} is reachable again.",
                null,
                null));
        }

        if (current.SnmpOk
            && previous?.SnmpOk == true
            && CounterMath.IsUptimeReset(previous.SysUpTimeTicks, current.SysUpTimeTicks))
        {
            transitions.Add(Open(
                $"{scope}:reboot:{current.SysUpTimeTicks}",
                AlertKind.DeviceReboot,
                AlertSeverity.Warning,
                $"Device {deviceName} rebooted (sysUpTime decreased).",
                null,
                null));
        }

        if (current.SnmpOk)
        {
            var seen = new HashSet<int>();
            foreach (var iface in current.Interfaces)
            {
                seen.Add(iface.IfIndex);
                var key = InterfaceDownKey(scope, iface.IfIndex);
                if (IsOperDown(iface) && IsAdminUp(iface))
                {
                    fired.Add(key);
                    if (!openKeys.Contains(key))
                    {
                        transitions.Add(Open(
                            key,
                            AlertKind.InterfaceDown,
                            AlertSeverity.Warning,
                            $"Interface {Label(iface)} on {deviceName} is down.",
                            iface.IfIndex,
                            null));
                    }
                }
                else if (openKeys.Contains(key))
                {
                    transitions.Add(Resolve(
                        key,
                        AlertKind.InterfaceDown,
                        AlertSeverity.Warning,
                        $"Interface {Label(iface)} on {deviceName} is up.",
                        iface.IfIndex,
                        null));
                    transitions.Add(Open(
                        $"{scope}:if:{iface.IfIndex}:up:{iface.OperStatus}",
                        AlertKind.InterfaceUp,
                        AlertSeverity.Info,
                        $"Interface {Label(iface)} on {deviceName} is up.",
                        iface.IfIndex,
                        null));
                }
            }

            foreach (var key in openKeys)
            {
                if (!TryParseInterfaceDown(scope, key, out var index) || seen.Contains(index))
                {
                    continue;
                }

                transitions.Add(Resolve(
                    key,
                    AlertKind.InterfaceDown,
                    AlertSeverity.Warning,
                    $"Interface {index} on {deviceName} disappeared from the interface table.",
                    index,
                    null));
            }

            foreach (var rule in rules)
            {
                if (IsInterfaceMetric(rule.Metric))
                {
                    foreach (var iface in current.Interfaces)
                    {
                        if (!FilterMatches(rule.InterfaceFilter, iface))
                        {
                            continue;
                        }

                        Consider(
                            rule,
                            $"{scope}:rule:{rule.Id}:if:{iface.IfIndex}",
                            MetricValue(rule.Metric, iface, current),
                            $"{deviceName} {Label(iface)}",
                            iface.IfIndex,
                            transitions,
                            fired,
                            openKeys);
                    }
                }
                else
                {
                    Consider(
                        rule,
                        $"{scope}:rule:{rule.Id}",
                        MetricValue(rule.Metric, null, current),
                        deviceName,
                        null,
                        transitions,
                        fired,
                        openKeys);
                }
            }

            var rulePrefix = $"{scope}:rule:";
            foreach (var key in openKeys)
            {
                if (!key.StartsWith(rulePrefix, StringComparison.Ordinal) || fired.Contains(key))
                {
                    continue;
                }

                transitions.Add(Resolve(
                    key,
                    AlertKind.Threshold,
                    AlertSeverity.Info,
                    $"Threshold cleared on {deviceName}.",
                    TryParseRuleInterface(key),
                    TryParseRuleId(key)));
            }
        }

        return transitions;
    }

    public static bool Compare(ThresholdOperator op, double value, double threshold)
    {
        return op switch
        {
            ThresholdOperator.GreaterThan => value > threshold,
            ThresholdOperator.GreaterOrEqual => value >= threshold,
            ThresholdOperator.LessThan => value < threshold,
            ThresholdOperator.LessOrEqual => value <= threshold,
            _ => false
        };
    }

    private static void Consider(
        AlertRuleModel rule,
        string key,
        double? value,
        string target,
        int? ifIndex,
        List<AlertTransition> transitions,
        HashSet<string> fired,
        IReadOnlySet<string> openKeys)
    {
        if (value is null || double.IsNaN(value.Value) || double.IsInfinity(value.Value))
        {
            return;
        }

        if (!Compare(rule.Operator, value.Value, rule.Threshold))
        {
            return;
        }

        fired.Add(key);
        if (openKeys.Contains(key))
        {
            return;
        }

        var op = rule.Operator switch
        {
            ThresholdOperator.GreaterThan => ">",
            ThresholdOperator.GreaterOrEqual => ">=",
            ThresholdOperator.LessThan => "<",
            ThresholdOperator.LessOrEqual => "<=",
            _ => "?"
        };

        transitions.Add(Open(
            key,
            AlertKind.Threshold,
            rule.Severity,
            $"{rule.Name}: {MetricLabel(rule.Metric)} on {target} is {FormatValue(rule.Metric, value.Value)} (threshold {op} {FormatValue(rule.Metric, rule.Threshold)}).",
            ifIndex,
            rule.Id));
    }

    private static bool IsInterfaceMetric(string metric)
    {
        return metric is "in_bps" or "out_bps" or "in_util" or "out_util";
    }

    private static bool IsOperDown(InterfaceSnapshot iface) => iface.OperStatus is 2 or 7;

    private static bool IsAdminUp(InterfaceSnapshot iface) => iface.AdminStatus != 2;

    private static bool FilterMatches(string? filter, InterfaceSnapshot iface)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return true;
        }

        return iface.Descr.Contains(filter, StringComparison.OrdinalIgnoreCase)
            || (iface.Name?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private static double? MetricValue(string metric, InterfaceSnapshot? iface, PollSnapshot current)
    {
        if (metric == "response_ms")
        {
            return current.ResponseMs;
        }

        if (metric.StartsWith("custom_rate:", StringComparison.Ordinal))
        {
            return Custom(current, metric["custom_rate:".Length..])?.RatePerSecond;
        }

        if (metric.StartsWith("custom:", StringComparison.Ordinal))
        {
            return Custom(current, metric["custom:".Length..])?.NumericValue;
        }

        if (iface is null)
        {
            return null;
        }

        return metric switch
        {
            "in_bps" => iface.InBps,
            "out_bps" => iface.OutBps,
            "in_util" => iface.InUtil,
            "out_util" => iface.OutUtil,
            _ => null
        };
    }

    private static CustomSnapshot? Custom(PollSnapshot current, string idText)
    {
        if (!int.TryParse(idText, out var id))
        {
            return null;
        }

        foreach (var custom in current.Customs)
        {
            if (custom.CustomOidId == id)
            {
                return custom;
            }
        }

        return null;
    }

    private static string InterfaceDownKey(string scope, int ifIndex) => $"{scope}:if:{ifIndex}:down";

    private static bool TryParseInterfaceDown(string scope, string key, out int index)
    {
        index = 0;
        var prefix = scope + ":if:";
        const string suffix = ":down";
        if (!key.StartsWith(prefix, StringComparison.Ordinal) || !key.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        var middle = key[prefix.Length..^suffix.Length];
        return int.TryParse(middle, out index);
    }

    private static int? TryParseRuleId(string key)
    {
        const string marker = ":rule:";
        var start = key.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        var rest = key[(start + marker.Length)..];
        var colon = rest.IndexOf(':');
        var number = colon >= 0 ? rest[..colon] : rest;
        return int.TryParse(number, out var id) ? id : null;
    }

    private static int? TryParseRuleInterface(string key)
    {
        const string marker = ":if:";
        var start = key.LastIndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        var rest = key[(start + marker.Length)..];
        return int.TryParse(rest, out var index) ? index : null;
    }

    private static string Label(InterfaceSnapshot iface)
    {
        if (!string.IsNullOrWhiteSpace(iface.Name) && !string.Equals(iface.Name, iface.Descr, StringComparison.Ordinal))
        {
            return $"{iface.Descr} ({iface.Name})";
        }

        return string.IsNullOrWhiteSpace(iface.Descr) ? $"if{iface.IfIndex}" : iface.Descr;
    }

    private static string MetricLabel(string metric) => metric switch
    {
        "response_ms" => "response time",
        "in_bps" => "inbound rate",
        "out_bps" => "outbound rate",
        "in_util" => "inbound utilization",
        "out_util" => "outbound utilization",
        _ when metric.StartsWith("custom_rate:", StringComparison.Ordinal) => "custom counter rate",
        _ when metric.StartsWith("custom:", StringComparison.Ordinal) => "custom OID",
        _ => metric
    };

    private static string FormatValue(string metric, double value)
    {
        if (metric is "in_bps" or "out_bps")
        {
            return CounterMath.FormatBitsPerSecond(value);
        }

        if (metric is "in_util" or "out_util")
        {
            return $"{value:0.##}%";
        }

        if (metric == "response_ms")
        {
            return $"{value:0.##} ms";
        }

        return value.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static AlertTransition Open(string key, AlertKind kind, AlertSeverity severity, string message, int? ifIndex, int? ruleId)
        => new(AlertTransitionType.Open, key, kind, severity, message, ifIndex, ruleId);

    private static AlertTransition Resolve(string key, AlertKind kind, AlertSeverity severity, string message, int? ifIndex, int? ruleId)
        => new(AlertTransitionType.Resolve, key, kind, severity, message, ifIndex, ruleId);
}
