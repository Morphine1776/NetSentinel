using NetSentinel.Core;

namespace NetSentinel.Tests;

public class CounterMathTests
{
    [Fact]
    public void Delta_counts_a_plain_increase()
    {
        Assert.Equal(4000ul, CounterMath.Delta(1000, 5000, 32));
        Assert.Equal(4000ul, CounterMath.Delta(1000, 5000, 64));
    }

    [Fact]
    public void Delta_handles_a_32_bit_wrap()
    {
        ulong previous = uint.MaxValue - 50;
        const ulong current = 100;
        Assert.Equal(151ul, CounterMath.Delta(previous, current, 32));
    }

    [Fact]
    public void Delta_handles_a_64_bit_wrap()
    {
        ulong previous = ulong.MaxValue - 5;
        const ulong current = 10;
        Assert.Equal(16ul, CounterMath.Delta(previous, current, 64));
    }

    [Fact]
    public void Delta_masks_high_bits_on_32_bit_counters()
    {
        ulong previous = (1UL << 32) | 10;
        ulong current = (2UL << 32) | 15;
        Assert.Equal(5ul, CounterMath.Delta(previous, current, 32));
    }

    [Fact]
    public void BitsPerSecond_uses_elapsed_time()
    {
        var bps = CounterMath.BitsPerSecond(1000, 5000, 32, 4, uptimeReset: false);
        Assert.Equal(8000d, bps);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void BitsPerSecond_rejects_a_non_positive_interval(double elapsed)
    {
        Assert.Null(CounterMath.BitsPerSecond(1, 2, 32, elapsed, false));
    }

    [Fact]
    public void BitsPerSecond_rejects_a_non_finite_interval()
    {
        Assert.Null(CounterMath.BitsPerSecond(1, 2, 64, double.NaN, false));
        Assert.Null(CounterMath.BitsPerSecond(1, 2, 64, double.PositiveInfinity, false));
    }

    [Fact]
    public void Reset_uses_the_new_counter_when_uptime_went_backwards()
    {
        var bps = CounterMath.BitsPerSecond(10_000, 100, 32, 1, uptimeReset: true);
        Assert.Equal(800d, bps);
    }

    [Fact]
    public void Reset_keeps_the_difference_when_the_counter_did_not_decrease()
    {
        var bps = CounterMath.BitsPerSecond(100, 200, 64, 1, uptimeReset: true);
        Assert.Equal(800d, bps);
    }

    [Fact]
    public void Wrap_rate_matches_the_modulo_delta()
    {
        ulong previous = uint.MaxValue - 50;
        var bps = CounterMath.BitsPerSecond(previous, 100, 32, 1, uptimeReset: false);
        Assert.Equal(151d * 8d, bps);
    }

    [Fact]
    public void Utilization_is_a_percent_of_link_speed()
    {
        var percent = CounterMath.UtilizationPercent(500_000_000, 1_000_000_000);
        Assert.Equal(50d, percent);
    }

    [Fact]
    public void Utilization_is_null_without_a_speed()
    {
        Assert.Null(CounterMath.UtilizationPercent(1000, 0));
        Assert.Null(CounterMath.UtilizationPercent(null, 1_000_000));
    }

    [Fact]
    public void Invalid_width_throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CounterMath.Delta(1, 2, 16));
    }

    [Fact]
    public void Uptime_reset_requires_a_decrease()
    {
        Assert.True(CounterMath.IsUptimeReset(10_000, 20));
        Assert.False(CounterMath.IsUptimeReset(10, 20));
        Assert.False(CounterMath.IsUptimeReset(null, 20));
        Assert.False(CounterMath.IsUptimeReset(10, null));
    }

    [Fact]
    public void Format_uses_decimal_units()
    {
        Assert.Equal("100 Mbps", CounterMath.FormatBitsPerSecond(100_000_000));
        Assert.Equal("1.5 Gbps", CounterMath.FormatBitsPerSecond(1_500_000_000));
        Assert.Equal("800 bps", CounterMath.FormatBitsPerSecond(800));
    }
}
