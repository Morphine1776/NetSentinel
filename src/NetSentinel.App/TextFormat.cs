using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel;

public static class TextFormat
{
    public static string Bps(double? bitsPerSecond)
        => bitsPerSecond is null ? "—" : CounterMath.FormatBitsPerSecond(bitsPerSecond.Value);

    public static string Speed(long packed)
    {
        var bits = CounterStorage.Unpack(packed);
        return bits == 0 ? "—" : CounterMath.FormatBitsPerSecond(bits);
    }

    public static string Uptime(long? ticks)
    {
        if (ticks is null || ticks < 0)
        {
            return "—";
        }

        var span = TimeSpan.FromSeconds(ticks.Value / 100.0);
        if (span.TotalDays >= 1)
        {
            return $"{(int)span.TotalDays}d {span.Hours}h {span.Minutes}m";
        }

        if (span.TotalHours >= 1)
        {
            return $"{(int)span.TotalHours}h {span.Minutes}m {span.Seconds}s";
        }

        return $"{span.Minutes}m {span.Seconds}s";
    }

    public static string When(DateTime? utc)
    {
        if (utc is null)
        {
            return "—";
        }

        var value = utc.Value.Kind == DateTimeKind.Utc ? utc.Value : DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc);
        return value.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
    }

    public static string Ms(int? milliseconds) => milliseconds is null ? "—" : $"{milliseconds} ms";

    public static string Percent(double? value) => value is null ? "—" : $"{value.Value:0.0}%";

    public static string Version(SnmpVersion version) => version switch
    {
        SnmpVersion.V1 => "v1",
        SnmpVersion.V2C => "v2c",
        SnmpVersion.V3 => "v3",
        _ => version.ToString()
    };

    public static string Reachability(Device device)
    {
        if (!device.Enabled)
        {
            return "Paused";
        }

        if (device.LastPollAt is null)
        {
            return "Pending";
        }

        if (device.LastSnmpOk != true)
        {
            return "Down";
        }

        if (device.LastPingOk == false)
        {
            return "Degraded";
        }

        return "Up";
    }

    public static string Lamp(Device device)
    {
        if (!device.Enabled || device.LastPollAt is null)
        {
            return "off";
        }

        if (device.LastSnmpOk != true)
        {
            return "down";
        }

        if (device.LastPingOk == false)
        {
            return "warn";
        }

        return "up";
    }

    public static string Ping(bool? pingOk) => pingOk switch
    {
        true => "ok",
        false => "fail",
        _ => "n/a"
    };

    public static string Oper(int status) => status switch
    {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "not present",
        7 => "lower layer down",
        _ => "—"
    };

    public static string Admin(int status) => status switch
    {
        1 => "up",
        2 => "down",
        3 => "testing",
        _ => "—"
    };

    public static string Severity(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => "critical",
        AlertSeverity.Warning => "warning",
        _ => "info"
    };

    public static string Kind(AlertKind kind) => kind switch
    {
        AlertKind.DeviceDown => "device down",
        AlertKind.DeviceUp => "device up",
        AlertKind.DeviceReboot => "reboot",
        AlertKind.InterfaceDown => "interface down",
        AlertKind.InterfaceUp => "interface up",
        AlertKind.Threshold => "threshold",
        _ => kind.ToString()
    };
}
