using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Polling;
using NetSentinel.Snmp;

namespace NetSentinel.Tests;

public class HaPollApplyTests
{
    [Fact]
    public void Failed_probe_keeps_last_ha_state_pending_and_raises_no_alert()
    {
        var checkedAt = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
        var device = Firewall();
        device.HaCheckedAt = checkedAt;
        device.HaPendingState = "";
        device.HaPendingCount = 1;

        var alert = PollWorker.ApplyHaResult(device, new PollResult
        {
            SnmpOk = true,
            HaRead = true,
            HaProbeFailed = true,
            HaState = null,
            HaPeerState = null,
            HaVendor = null,
            SampledAt = checkedAt.AddMinutes(1)
        }, alertOnHaChange: true);

        Assert.Null(alert);
        Assert.Equal("passive", device.HaState);
        Assert.Equal("active", device.HaPeerState);
        Assert.Equal("paloalto", device.HaVendor);
        Assert.Equal("", device.HaPendingState);
        Assert.Equal(1, device.HaPendingCount);
        Assert.Equal(checkedAt, device.HaCheckedAt);
    }

    [Fact]
    public void Worker_debounces_na_and_alerts_a_real_role_change_immediately()
    {
        var device = Firewall();
        device.HaCheckedAt = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
        var sampled = device.HaCheckedAt.Value.AddMinutes(1);

        var first = PollWorker.ApplyHaResult(device, Reading(null, sampled), alertOnHaChange: true);
        Assert.Null(first);
        Assert.Equal("passive", device.HaState);
        Assert.Equal("", device.HaPendingState);
        Assert.Equal(1, device.HaPendingCount);

        var back = PollWorker.ApplyHaResult(device, Reading("passive", sampled.AddMinutes(1), peer: "active"), alertOnHaChange: true);
        Assert.Null(back);
        Assert.Equal("passive", device.HaState);
        Assert.Null(device.HaPendingState);
        Assert.Equal(0, device.HaPendingCount);

        var role = PollWorker.ApplyHaResult(device, Reading("active", sampled.AddMinutes(2), peer: "passive"), alertOnHaChange: true);
        Assert.NotNull(role);
        Assert.Equal(AlertKind.HaChange, role!.Kind);
        Assert.Equal("active", device.HaState);
        Assert.Equal("passive", device.HaPeerState);
        Assert.Equal(sampled.AddMinutes(2), device.HaCheckedAt);
        Assert.Contains("passive", role.Message, StringComparison.Ordinal);
        Assert.Contains("active", role.Message, StringComparison.Ordinal);

        device.HaState = "active";
        var muted = PollWorker.ApplyHaResult(device, Reading("passive", sampled.AddMinutes(3)), alertOnHaChange: false);
        Assert.Null(muted);
        Assert.Equal("passive", device.HaState);
    }

    [Fact]
    public void First_successful_reading_is_stored_without_an_alert()
    {
        var device = Firewall();
        device.HaState = null;
        device.HaCheckedAt = null;
        var sampled = new DateTime(2026, 11, 2, 8, 0, 0, DateTimeKind.Utc);

        var alert = PollWorker.ApplyHaResult(device, Reading("active", sampled, peer: "passive"), alertOnHaChange: true);
        Assert.Null(alert);
        Assert.Equal("active", device.HaState);
        Assert.Equal("passive", device.HaPeerState);
        Assert.Equal(sampled, device.HaCheckedAt);
        Assert.Equal(0, device.HaPendingCount);
    }

    [Fact]
    public void Snmp_failure_does_not_touch_ha_fields()
    {
        var device = Firewall();
        var alert = PollWorker.ApplyHaResult(device, new PollResult
        {
            SnmpOk = false,
            HaRead = true,
            HaProbeFailed = true,
            HaState = null
        }, alertOnHaChange: true);

        Assert.Null(alert);
        Assert.Equal("passive", device.HaState);
        Assert.Equal("active", device.HaPeerState);
        Assert.Equal("paloalto", device.HaVendor);
    }

    private static Device Firewall() => new()
    {
        Id = 7,
        Name = "fw",
        HaState = "passive",
        HaPeerState = "active",
        HaVendor = "paloalto"
    };

    private static PollResult Reading(string? state, DateTime sampled, string? peer = null) => new()
    {
        SnmpOk = true,
        HaRead = true,
        HaState = state,
        HaPeerState = peer,
        HaVendor = "paloalto",
        SampledAt = sampled
    };
}
