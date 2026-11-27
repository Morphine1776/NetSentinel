using NetSentinel.Core;

namespace NetSentinel.Tests;

public class HaStatusTests
{
    [Theory]
    [InlineData("active", HaBadge.Active, "Active")]
    [InlineData("PASSIVE", HaBadge.Passive, "Passive")]
    [InlineData("suspended", HaBadge.Other, "Suspended")]
    [InlineData("initial", HaBadge.Other, "Initial")]
    [InlineData("non-functional", HaBadge.Other, "Non-functional")]
    [InlineData("tentative", HaBadge.Other, "Tentative")]
    public void Palo_alto_strings_map_to_badges(string raw, HaBadge badge, string label)
    {
        var vendor = new PaloAltoHaVendor();
        var answer = vendor.Interpret(raw, missing: false);
        Assert.True(answer.Answered);
        var reading = vendor.ToReading(answer.Raw, "passive");
        Assert.Equal(badge, reading.Badge);
        Assert.Equal(label, reading.Label);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", false)]
    [InlineData("disabled", false)]
    [InlineData("noSuchObject", false)]
    [InlineData("noSuchInstance", false)]
    public void Missing_empty_or_disabled_palo_alto_state_is_not_a_role(string? raw, bool missing)
    {
        var vendor = new PaloAltoHaVendor();
        var answer = vendor.Interpret(raw, missing);
        if (missing || HaStatus.IsMissingToken(raw))
        {
            Assert.False(answer.Answered);
        }
        else
        {
            Assert.True(answer.Answered);
            Assert.Null(answer.Raw);
        }

        Assert.Equal(HaBadge.Unavailable, vendor.ToReading(null, null).Badge);
        Assert.Equal("N/A", vendor.ToReading(null, null).Label);
    }

    [Theory]
    [InlineData("14", "active", HaBadge.Active)]
    [InlineData("9", "passive", HaBadge.Passive)]
    [InlineData("2", null, HaBadge.Unavailable)]
    [InlineData("1", null, HaBadge.Unavailable)]
    [InlineData("3", "initialization", HaBadge.Other)]
    [InlineData("standby-hot", "passive", HaBadge.Passive)]
    public void Cisco_redundancy_framework_values_map_to_badges(string raw, string? token, HaBadge badge)
    {
        var vendor = new CiscoRfHaVendor();
        var answer = vendor.Interpret(raw, missing: false);
        Assert.True(answer.Answered);
        Assert.Equal(token, answer.Raw);
        Assert.Equal(badge, vendor.ToReading(answer.Raw, null).Badge);
    }

    [Fact]
    public void Vendors_are_tried_in_order_and_a_missing_oid_falls_through()
    {
        var reading = HaStatus.Resolve(oids =>
        {
            var joined = string.Join(",", oids);
            if (joined.Contains("25461", StringComparison.Ordinal))
            {
                return new HaProbeAnswer(false, null);
            }

            if (joined.Contains("9.9.176", StringComparison.Ordinal))
            {
                return new HaProbeAnswer(true, "14");
            }

            return new HaProbeAnswer(false, null);
        });

        Assert.Equal(HaBadge.Active, reading.Badge);
        Assert.Equal("cisco-rf", reading.Vendor);
    }

    [Theory]
    [InlineData("1.3.6.1.4.1.25461.2.3.1", null, true)]
    [InlineData(".1.3.6.1.4.1.25461.2.3", null, true)]
    [InlineData(null, "Palo Alto Networks PA-3440 series firewall", true)]
    [InlineData(null, "PAN-OS 11.1", true)]
    [InlineData("1.3.6.1.4.1.9.1.123", "Cisco IOS", false)]
    [InlineData(null, "NetSentinel Simulator", false)]
    public void Palo_alto_detection_uses_sysobjectid_or_sysdescr(string? sysObjectId, string? sysDescr, bool expected)
    {
        Assert.Equal(expected, HaStatus.LooksLikePaloAlto(sysObjectId, sysDescr));
    }

    [Fact]
    public void Every_device_is_polled_for_ha_and_palo_alto_is_tried_first_when_detected()
    {
        var vendors = HaStatus.ForDevice("1.3.6.1.4.1.25461.2.3.4", "PA-3440");
        Assert.Equal("paloalto", vendors[0].Id);
        Assert.Contains(vendors, vendor => vendor.Id == "cisco-rf");

        var unknown = HaStatus.ForDevice(null, "NetSentinel Simulator");
        Assert.Equal(2, unknown.Count);
        Assert.Equal("N/A", HaStatus.FromStored(null, null, null, snmpOk: true).Label);
        Assert.Equal("N/A", HaStatus.FromStored(null, null, null, snmpOk: false).Label);
        Assert.Equal("active", new PaloAltoHaVendor().Interpret("active\0", missing: false).Raw);
    }

    [Fact]
    public void Ha_change_alerts_only_after_a_previous_reading_and_only_when_enabled()
    {
        Assert.Null(HaAlerts.Change("device:1", "fw", hadReading: false, null, "active", enabled: true));
        Assert.Null(HaAlerts.Change("device:1", "fw", hadReading: true, "active", "active", enabled: true));
        Assert.Null(HaAlerts.Change("device:1", "fw", hadReading: true, "active", "passive", enabled: false));

        var alert = HaAlerts.Change("device:1", "fw", hadReading: true, "active", "passive", enabled: true);
        Assert.NotNull(alert);
        Assert.Equal(AlertKind.HaChange, alert!.Kind);
        Assert.Equal(AlertSeverity.Info, alert.Severity);
        Assert.Contains("active", alert.Message, StringComparison.Ordinal);
        Assert.Contains("passive", alert.Message, StringComparison.Ordinal);

        var cleared = HaAlerts.Change("device:1", "fw", hadReading: true, "passive", null, enabled: true);
        Assert.NotNull(cleared);
        Assert.Contains("N/A", cleared!.Message, StringComparison.Ordinal);
    }
}
