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
    public void Identified_vendors_are_probed_alone_and_unknown_devices_try_both()
    {
        var palo = HaStatus.ForDevice("1.3.6.1.4.1.25461.2.3.4", "PA-3440");
        Assert.Equal("paloalto", Assert.Single(palo).Id);

        var cisco = HaStatus.ForDevice("1.3.6.1.4.1.9.1.123", "Cisco IOS");
        Assert.Equal("cisco-rf", Assert.Single(cisco).Id);

        var unknown = HaStatus.ForDevice(null, "NetSentinel Simulator");
        Assert.Equal(new[] { "paloalto", "cisco-rf" }, unknown.Select(vendor => vendor.Id).ToArray());
        Assert.Equal("N/A", HaStatus.FromStored(null, null, null, snmpOk: true).Label);
        Assert.Equal("N/A", HaStatus.FromStored(null, null, null, snmpOk: false).Label);
        Assert.Equal("active", new PaloAltoHaVendor().Interpret("active\0", missing: false).Raw);
    }

    [Fact]
    public void A_known_vendor_does_not_query_the_other_vendors_oids()
    {
        var paloSeen = new List<string>();
        var palo = HaStatus.Resolve(
            oids =>
            {
                paloSeen.Add(string.Join(",", oids));
                return new HaProbeAnswer(true, "active");
            },
            HaStatus.ForDevice("1.3.6.1.4.1.25461.2.3", "PA-3440"));
        Assert.Equal("active", palo.Token);
        Assert.False(palo.ProbeFailed);
        Assert.All(paloSeen, item => Assert.DoesNotContain("9.9.176", item, StringComparison.Ordinal));

        var ciscoSeen = new List<string>();
        var cisco = HaStatus.Resolve(
            oids =>
            {
                ciscoSeen.Add(string.Join(",", oids));
                return new HaProbeAnswer(true, "14");
            },
            HaStatus.ForDevice("1.3.6.1.4.1.9.1.1", "Cisco IOS"));
        Assert.Equal("active", cisco.Token);
        Assert.All(ciscoSeen, item => Assert.DoesNotContain("25461", item, StringComparison.Ordinal));
    }

    [Fact]
    public void Unanswered_probes_fail_and_an_answered_disabled_is_real_na()
    {
        var failed = HaStatus.Resolve(_ => new HaProbeAnswer(false, null));
        Assert.True(failed.ProbeFailed);
        Assert.Null(failed.Token);
        Assert.Equal(HaBadge.Unavailable, failed.Badge);

        var missing = HaStatus.Resolve(_ => new HaProbeAnswer(true, "noSuchObject"));
        Assert.True(missing.ProbeFailed);

        var disabled = HaStatus.Resolve(oids =>
            string.Join(",", oids).Contains("25461.2.1.2.1.11", StringComparison.Ordinal)
                ? new HaProbeAnswer(true, "disabled")
                : new HaProbeAnswer(false, null));
        Assert.False(disabled.ProbeFailed);
        Assert.Null(disabled.Token);
        Assert.Equal("paloalto", disabled.Vendor);
    }

    [Fact]
    public void Ha_change_alerts_only_after_a_previous_reading_and_only_when_enabled()
    {
        var first = Observe(current: null, next: "active", hadReading: false);
        Assert.Null(first.Alert);
        Assert.Equal("active", first.State);
        Assert.Equal(0, first.PendingCount);

        var same = Observe("active", "active");
        Assert.Null(same.Alert);
        Assert.Equal("active", same.State);
        Assert.Equal(0, same.PendingCount);

        var muted = Observe("active", "passive", enabled: false);
        Assert.Null(muted.Alert);
        Assert.Equal("passive", muted.State);
        Assert.Equal(0, muted.PendingCount);

        var alert = Observe("active", "passive");
        Assert.NotNull(alert.Alert);
        Assert.Equal("passive", alert.State);
        Assert.Equal(AlertKind.HaChange, alert.Alert!.Kind);
        Assert.Equal(AlertSeverity.Info, alert.Alert.Severity);
        Assert.Contains("active", alert.Alert.Message, StringComparison.Ordinal);
        Assert.Contains("passive", alert.Alert.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Failed_read_keeps_the_state_and_raises_no_alert()
    {
        var decision = Observe("passive", next: null, pending: "", count: 1, probeFailed: true, peer: "active", nextPeer: "gone");
        Assert.Null(decision.Alert);
        Assert.Equal("passive", decision.State);
        Assert.Equal("active", decision.Peer);
        Assert.Equal("paloalto", decision.Vendor);
        Assert.Equal("", decision.PendingState);
        Assert.Equal(1, decision.PendingCount);
    }

    [Fact]
    public void Na_then_passive_needs_two_confirmations()
    {
        var once = Observe(current: null, next: "passive", peer: "standby");
        Assert.Null(once.Alert);
        Assert.Null(once.State);
        Assert.Equal("standby", once.Peer);
        Assert.Equal("passive", once.PendingState);
        Assert.Equal(1, once.PendingCount);

        var other = Observe(current: null, next: "active", pending: once.PendingState, count: once.PendingCount, peer: "standby");
        Assert.Null(other.Alert);
        Assert.Null(other.State);
        Assert.Equal("active", other.PendingState);
        Assert.Equal(1, other.PendingCount);

        var twice = Observe(current: null, next: "passive", pending: "passive", count: 1, peer: "standby", nextPeer: "active");
        Assert.NotNull(twice.Alert);
        Assert.Equal("passive", twice.State);
        Assert.Equal("active", twice.Peer);
        Assert.Equal(0, twice.PendingCount);
        Assert.Null(twice.PendingState);
        Assert.Contains("N/A", twice.Alert!.Message, StringComparison.Ordinal);
        Assert.Contains("passive", twice.Alert.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Passive_then_na_needs_two_confirmations()
    {
        var once = Observe("passive", next: null, peer: "active", nextPeer: "gone");
        Assert.Null(once.Alert);
        Assert.Equal("passive", once.State);
        Assert.Equal("active", once.Peer);
        Assert.Equal("", once.PendingState);
        Assert.Equal(1, once.PendingCount);

        var twice = Observe("passive", next: null, pending: "", count: 1, peer: "active", nextPeer: null, nextVendor: "paloalto");
        Assert.NotNull(twice.Alert);
        Assert.Null(twice.State);
        Assert.Equal(0, twice.PendingCount);
        Assert.Contains("passive", twice.Alert!.Message, StringComparison.Ordinal);
        Assert.Contains("N/A", twice.Alert.Message, StringComparison.Ordinal);

        var muted = Observe("passive", next: null, pending: "", count: 1, enabled: false);
        Assert.Null(muted.Alert);
        Assert.Null(muted.State);
    }

    [Fact]
    public void A_single_blip_back_to_the_old_value_clears_pending_without_an_alert()
    {
        var blip = Observe("passive", next: null, peer: "active");
        Assert.Null(blip.Alert);
        Assert.Equal(1, blip.PendingCount);

        var back = Observe("passive", next: "passive", pending: blip.PendingState, count: blip.PendingCount, peer: "active", nextPeer: "active");
        Assert.Null(back.Alert);
        Assert.Equal("passive", back.State);
        Assert.Equal("active", back.Peer);
        Assert.Null(back.PendingState);
        Assert.Equal(0, back.PendingCount);
    }

    [Theory]
    [InlineData("active", "passive")]
    [InlineData("passive", "active")]
    [InlineData("active", "suspended")]
    [InlineData("passive", "non-functional")]
    [InlineData("suspended", "active")]
    public void Known_role_changes_alert_immediately(string from, string to)
    {
        var decision = Observe(from, to, pending: "", count: 1);
        Assert.NotNull(decision.Alert);
        Assert.Equal(to, decision.State);
        Assert.Equal(0, decision.PendingCount);
        Assert.Null(decision.PendingState);
        Assert.Contains(from, decision.Alert!.Message, StringComparison.Ordinal);
        Assert.Contains(to, decision.Alert.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Disabled_is_an_answered_na_and_still_debounces()
    {
        var vendor = new PaloAltoHaVendor();
        var answer = vendor.Interpret("disabled", missing: false);
        Assert.True(answer.Answered);
        Assert.Null(answer.Raw);
        var reading = vendor.ToReading(answer.Raw, "active");
        Assert.False(reading.ProbeFailed);
        Assert.Null(reading.Token);
        Assert.Equal("paloalto", reading.Vendor);

        var once = Observe("passive", reading.Token, peer: "active", nextPeer: reading.Peer, nextVendor: reading.Vendor);
        Assert.Null(once.Alert);
        Assert.Equal("passive", once.State);
        Assert.Equal("active", once.Peer);
        Assert.Equal("", once.PendingState);
        Assert.Equal(1, once.PendingCount);

        var twice = Observe("passive", reading.Token, pending: once.PendingState, count: once.PendingCount, nextPeer: reading.Peer, nextVendor: reading.Vendor);
        Assert.NotNull(twice.Alert);
        Assert.Null(twice.State);
        Assert.Contains("N/A", twice.Alert!.Message, StringComparison.Ordinal);
        Assert.Equal(0, twice.PendingCount);
    }

    private static HaDecision Observe(
        string? current,
        string? next,
        string? pending = null,
        int count = 0,
        bool hadReading = true,
        bool enabled = true,
        bool probeFailed = false,
        string? peer = "active",
        string? vendor = "paloalto",
        string? nextPeer = null,
        string? nextVendor = "paloalto")
        => HaAlerts.Observe(
            "device:1",
            "fw",
            new HaTrack(hadReading, current, peer, vendor, pending, count),
            next,
            nextPeer,
            nextVendor,
            enabled,
            probeFailed);
}
