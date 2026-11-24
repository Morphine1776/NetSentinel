using NetSentinel.Core;

namespace NetSentinel.Tests;

public class AlertEvaluatorTests
{
    private const string Scope = "device:7";

    [Fact]
    public void Device_down_waits_for_the_failure_threshold()
    {
        var transitions = Evaluate(snmpOk: false, failures: 1, threshold: 2, open: Empty());
        Assert.DoesNotContain(transitions, item => item.Kind == AlertKind.DeviceDown);
    }

    [Fact]
    public void Device_down_opens_at_the_threshold_and_mentions_ping()
    {
        var transitions = Evaluate(snmpOk: false, ping: false, failures: 2, threshold: 2, open: Empty());
        var alert = Assert.Single(transitions);
        Assert.Equal(AlertKind.DeviceDown, alert.Kind);
        Assert.Equal(AlertSeverity.Critical, alert.Severity);
        Assert.Contains("unreachable", alert.Message);
        Assert.Contains("Ping failed", alert.Message);
    }

    [Fact]
    public void Device_down_notes_when_ping_still_works()
    {
        var transitions = Evaluate(snmpOk: false, ping: true, failures: 1, threshold: 1, open: Empty());
        Assert.Contains("answers ping", Assert.Single(transitions).Message);
    }

    [Fact]
    public void Device_down_is_not_duplicated()
    {
        var open = Keys($"{Scope}:down");
        var transitions = Evaluate(snmpOk: false, failures: 3, threshold: 2, open: open);
        Assert.DoesNotContain(transitions, item => item.Type == AlertTransitionType.Open);
    }

    [Fact]
    public void Recovery_resolves_down_and_opens_an_up_alert()
    {
        var open = Keys($"{Scope}:down");
        var transitions = Evaluate(snmpOk: true, failures: 0, threshold: 2, open: open, previousDown: true);
        Assert.Contains(transitions, item => item.Type == AlertTransitionType.Resolve && item.Kind == AlertKind.DeviceDown);
        Assert.Contains(transitions, item => item.Type == AlertTransitionType.Open && item.Kind == AlertKind.DeviceUp);
    }

    [Fact]
    public void A_brief_blip_does_not_raise_a_recovery_alert()
    {
        var transitions = Evaluate(snmpOk: true, failures: 0, threshold: 2, open: Empty(), previousDown: true);
        Assert.DoesNotContain(transitions, item => item.Kind is AlertKind.DeviceUp or AlertKind.DeviceDown);
    }

    [Fact]
    public void Interface_down_alerts_only_when_admin_is_up()
    {
        var current = Snapshot(true, new InterfaceSnapshot(2, "Gi0/2", "Gi0/2", 1, 2, null, null, null, null));
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), Empty());
        var alert = Assert.Single(transitions);
        Assert.Equal(AlertKind.InterfaceDown, alert.Kind);
        Assert.Equal(2, alert.IfIndex);
    }

    [Fact]
    public void Administratively_down_interfaces_stay_quiet()
    {
        var current = Snapshot(true, new InterfaceSnapshot(2, "Gi0/2", "Gi0/2", 2, 2, null, null, null, null));
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), Empty());
        Assert.Empty(transitions);
    }

    [Fact]
    public void Lower_layer_down_is_treated_as_down()
    {
        var current = Snapshot(true, new InterfaceSnapshot(3, "Gi0/3", null, 1, 7, null, null, null, null));
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), Empty());
        Assert.Equal(AlertKind.InterfaceDown, Assert.Single(transitions).Kind);
    }

    [Fact]
    public void Interface_recovery_resolves_the_open_alert()
    {
        var current = Snapshot(true, new InterfaceSnapshot(2, "Gi0/2", "Gi0/2", 1, 1, null, null, null, null));
        var open = Keys($"{Scope}:if:2:down");
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), open);
        Assert.Contains(transitions, item => item.Type == AlertTransitionType.Resolve && item.Kind == AlertKind.InterfaceDown);
        Assert.Contains(transitions, item => item.Kind == AlertKind.InterfaceUp);
    }

    [Fact]
    public void A_missing_interface_resolves_its_down_alert()
    {
        var current = Snapshot(true);
        var open = Keys($"{Scope}:if:9:down");
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), open);
        Assert.Contains(transitions, item => item.Message.Contains("disappeared"));
    }

    [Fact]
    public void An_snmp_outage_does_not_clear_interface_or_threshold_alerts()
    {
        var current = new PollSnapshot(false, false, null, null, Array.Empty<InterfaceSnapshot>(), Array.Empty<CustomSnapshot>());
        var open = Keys($"{Scope}:if:2:down", $"{Scope}:rule:4:if:2");
        var rules = new[] { Rule(4, "in_util", 80) };
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 2, 2, rules, open);
        Assert.DoesNotContain(transitions, item => item.Type == AlertTransitionType.Resolve && item.Kind != AlertKind.DeviceDown);
        Assert.Contains(transitions, item => item.Kind == AlertKind.DeviceDown);
    }

    [Fact]
    public void Reboot_is_reported_when_uptime_decreases()
    {
        var previous = new PollSnapshot(true, true, 5, 50_000, Array.Empty<InterfaceSnapshot>(), Array.Empty<CustomSnapshot>());
        var current = new PollSnapshot(true, true, 6, 100, Array.Empty<InterfaceSnapshot>(), Array.Empty<CustomSnapshot>());
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", previous, current, 0, 2, Array.Empty<AlertRuleModel>(), Empty());
        Assert.Contains(transitions, item => item.Kind == AlertKind.DeviceReboot);
    }

    [Fact]
    public void Threshold_greater_than_fires_and_equal_does_not()
    {
        var rules = new[] { Rule(3, "response_ms", 50) };
        var above = Snapshot(true, response: 51);
        var equal = Snapshot(true, response: 50);
        Assert.Contains(
            AlertEvaluator.Evaluate(Scope, "edge", null, above, 0, 2, rules, Empty()),
            item => item.Kind == AlertKind.Threshold && item.RuleId == 3);
        Assert.DoesNotContain(
            AlertEvaluator.Evaluate(Scope, "edge", null, equal, 0, 2, rules, Empty()),
            item => item.Kind == AlertKind.Threshold);
    }

    [Fact]
    public void Threshold_greater_or_equal_fires_on_equal()
    {
        var rules = new[] { new AlertRuleModel(3, "slow", "response_ms", null, ThresholdOperator.GreaterOrEqual, 50, AlertSeverity.Warning) };
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, Snapshot(true, response: 50), 0, 2, rules, Empty());
        Assert.Contains(transitions, item => item.Kind == AlertKind.Threshold);
    }

    [Fact]
    public void Threshold_less_than_and_clear_resolve_the_open_alert()
    {
        var rules = new[] { new AlertRuleModel(8, "quiet", "in_bps", null, ThresholdOperator.LessThan, 1000, AlertSeverity.Info) };
        var low = Snapshot(true, new InterfaceSnapshot(1, "Gi0/0", "Gi0/0", 1, 1, 100, 0, 0, 0));
        var open = AlertEvaluator.Evaluate(Scope, "edge", null, low, 0, 2, rules, Empty());
        Assert.Contains(open, item => item.Type == AlertTransitionType.Open);

        var high = Snapshot(true, new InterfaceSnapshot(1, "Gi0/0", "Gi0/0", 1, 1, 5000, 0, 0, 0));
        var cleared = AlertEvaluator.Evaluate(Scope, "edge", null, high, 0, 2, rules, Keys($"{Scope}:rule:8:if:1"));
        Assert.Contains(cleared, item => item.Type == AlertTransitionType.Resolve && item.RuleId == 8);
    }

    [Fact]
    public void Interface_filter_limits_the_match()
    {
        var rules = new[] { new AlertRuleModel(5, "uplink", "in_util", "Gi0/0", ThresholdOperator.GreaterThan, 10, AlertSeverity.Warning) };
        var current = Snapshot(
            true,
            new InterfaceSnapshot(1, "Gi0/0", "uplink", 1, 1, null, null, 50, 1),
            new InterfaceSnapshot(2, "Gi0/1", "access", 1, 1, null, null, 90, 1));
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, rules, Empty());
        var alert = Assert.Single(transitions, item => item.Kind == AlertKind.Threshold);
        Assert.Equal(1, alert.IfIndex);
        Assert.Contains("Gi0/0", alert.Message);
    }

    [Fact]
    public void Custom_value_and_rate_metrics_fire()
    {
        var customs = new[] { new CustomSnapshot(5, "temp", 90, 12) };
        var current = new PollSnapshot(true, true, 4, 1000, Array.Empty<InterfaceSnapshot>(), customs);
        var valueRule = new AlertRuleModel(1, "hot", "custom:5", null, ThresholdOperator.GreaterThan, 80, AlertSeverity.Critical);
        var rateRule = new AlertRuleModel(2, "climbing", "custom_rate:5", null, ThresholdOperator.GreaterThan, 5, AlertSeverity.Warning);
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, new[] { valueRule, rateRule }, Empty());
        Assert.Equal(2, transitions.Count(item => item.Kind == AlertKind.Threshold));
    }

    [Fact]
    public void Unmonitored_interfaces_do_not_open_down_or_threshold_alerts()
    {
        var rules = new[] { new AlertRuleModel(3, "hot", "in_util", null, ThresholdOperator.GreaterThan, 10, AlertSeverity.Warning) };
        var current = Snapshot(true, new InterfaceSnapshot(4, "Gi1/0/4", "Gi1/0/4", 1, 2, null, null, 99, 80, false));
        var transitions = AlertEvaluator.Evaluate(Scope, "core", null, current, 0, 2, rules, Empty());
        Assert.Empty(transitions);
    }

    [Fact]
    public void Unmonitoring_resolves_an_open_interface_alert_without_an_up_notice()
    {
        var current = Snapshot(true, new InterfaceSnapshot(2, "Gi0/2", "Gi0/2", 1, 2, null, null, null, null, false));
        var transitions = AlertEvaluator.Evaluate(Scope, "core", null, current, 0, 2, Array.Empty<AlertRuleModel>(), Keys($"{Scope}:if:2:down"));
        var resolved = Assert.Single(transitions);
        Assert.Equal(AlertTransitionType.Resolve, resolved.Type);
        Assert.Equal(AlertKind.InterfaceDown, resolved.Kind);
        Assert.Contains("no longer monitored", resolved.Message);
    }

    [Fact]
    public void A_disabled_rule_clears_because_it_is_not_evaluated()
    {
        var current = Snapshot(true, response: 10);
        var transitions = AlertEvaluator.Evaluate(Scope, "edge", null, current, 0, 2, Array.Empty<AlertRuleModel>(), Keys($"{Scope}:rule:4"));
        Assert.Contains(transitions, item => item.Type == AlertTransitionType.Resolve && item.DedupKey == $"{Scope}:rule:4");
    }

    private static List<AlertTransition> Evaluate(
        bool snmpOk,
        int failures,
        int threshold,
        IReadOnlySet<string> open,
        bool? ping = null,
        bool previousDown = false)
    {
        PollSnapshot? previous = previousDown
            ? new PollSnapshot(false, false, null, 1000, Array.Empty<InterfaceSnapshot>(), Array.Empty<CustomSnapshot>())
            : null;
        var current = new PollSnapshot(snmpOk, ping, snmpOk ? 5 : null, snmpOk ? 2000 : null, Array.Empty<InterfaceSnapshot>(), Array.Empty<CustomSnapshot>());
        return AlertEvaluator.Evaluate(Scope, "edge", previous, current, failures, threshold, Array.Empty<AlertRuleModel>(), open);
    }

    private static PollSnapshot Snapshot(bool snmpOk, params InterfaceSnapshot[] interfaces)
        => Snapshot(snmpOk, 5, interfaces);

    private static PollSnapshot Snapshot(bool snmpOk, int? response = 5, params InterfaceSnapshot[] interfaces)
        => new(snmpOk, true, response, 1000, interfaces, Array.Empty<CustomSnapshot>());

    private static AlertRuleModel Rule(int id, string metric, double threshold)
        => new(id, "rule", metric, null, ThresholdOperator.GreaterThan, threshold, AlertSeverity.Warning);

    private static HashSet<string> Keys(params string[] keys) => new(keys, StringComparer.Ordinal);

    private static IReadOnlySet<string> Empty() => Keys();
}
