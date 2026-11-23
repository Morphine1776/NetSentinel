namespace NetSentinel.Core;

/// <summary>
/// Counter-delta and bandwidth math for 32-bit and 64-bit SNMP counters.
/// </summary>
public static class CounterMath
{
    public static ulong Delta(ulong previous, ulong current, int bits)
    {
        if (bits != 32 && bits != 64)
        {
            throw new ArgumentOutOfRangeException(nameof(bits), "Counter width must be 32 or 64.");
        }

        if (bits == 64)
        {
            return unchecked(current - previous);
        }

        var previous32 = previous & 0xFFFF_FFFFUL;
        var current32 = current & 0xFFFF_FFFFUL;
        return (current32 - previous32) & 0xFFFF_FFFFUL;
    }

    public static bool Decreased(ulong previous, ulong current, int bits)
    {
        if (bits == 64)
        {
            return current < previous;
        }

        return (current & 0xFFFF_FFFFUL) < (previous & 0xFFFF_FFFFUL);
    }

    /// <summary>
    /// Octets transferred between two samples. A backwards sysUpTime means the
    /// counter restarted, so a decrease is the new count rather than a wrap.
    /// </summary>
    public static ulong? CounterDelta(ulong previous, ulong current, int bits, double elapsedSeconds, bool uptimeReset)
    {
        if (!IsUsableInterval(elapsedSeconds))
        {
            return null;
        }

        if (uptimeReset && Decreased(previous, current, bits))
        {
            return bits == 64 ? current : current & 0xFFFF_FFFFUL;
        }

        return Delta(previous, current, bits);
    }

    public static double? UnitsPerSecond(ulong previous, ulong current, int bits, double elapsedSeconds, bool uptimeReset)
    {
        var delta = CounterDelta(previous, current, bits, elapsedSeconds, uptimeReset);
        if (delta is null)
        {
            return null;
        }

        return delta.Value / elapsedSeconds;
    }

    public static double? BitsPerSecond(ulong previous, ulong current, int bits, double elapsedSeconds, bool uptimeReset)
    {
        var units = UnitsPerSecond(previous, current, bits, elapsedSeconds, uptimeReset);
        return units * 8.0;
    }

    public static double? UtilizationPercent(double? bitsPerSecond, double speedBitsPerSecond)
    {
        if (bitsPerSecond is null || speedBitsPerSecond <= 0 || double.IsNaN(speedBitsPerSecond))
        {
            return null;
        }

        return bitsPerSecond.Value / speedBitsPerSecond * 100.0;
    }

    public static bool IsUptimeReset(long? previousTicks, long? currentTicks)
    {
        return previousTicks is > 0 && currentTicks is long current && current < previousTicks.Value;
    }

    public static string FormatBitsPerSecond(double bitsPerSecond)
    {
        var sign = bitsPerSecond < 0 ? "-" : "";
        var value = Math.Abs(bitsPerSecond);
        if (value >= 1_000_000_000d)
        {
            return $"{sign}{value / 1_000_000_000d:0.##} Gbps";
        }

        if (value >= 1_000_000d)
        {
            return $"{sign}{value / 1_000_000d:0.##} Mbps";
        }

        if (value >= 1_000d)
        {
            return $"{sign}{value / 1_000d:0.##} Kbps";
        }

        return $"{sign}{value:0} bps";
    }

    private static bool IsUsableInterval(double elapsedSeconds)
    {
        return elapsedSeconds > 0 && !double.IsNaN(elapsedSeconds) && !double.IsInfinity(elapsedSeconds);
    }
}
