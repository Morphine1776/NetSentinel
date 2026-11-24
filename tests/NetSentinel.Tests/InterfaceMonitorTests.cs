using NetSentinel.Core;

namespace NetSentinel.Tests;

public class InterfaceMonitorTests
{
    private static InterfaceIdentity Port(string name, string alias = "", int admin = 1, string? descr = null)
        => new(name, descr ?? name, alias, admin);

    [Fact]
    public void Default_rules_monitor_every_port()
    {
        Assert.True(InterfaceMonitor.Evaluate(Port("Gi1/0/4"), InterfaceMonitorRules.MonitorAll, null));
        Assert.True(InterfaceMonitor.FollowsRules(Port("Gi1/0/4", admin: 2), InterfaceMonitorRules.MonitorAll));
    }

    [Fact]
    public void Glob_exclude_drops_access_ports_and_keeps_uplinks()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { ExcludePattern = "Gi1/0/*" };
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/1"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/24"), rules));
        Assert.True(InterfaceMonitor.FollowsRules(Port("Gi0/0", "uplink"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("gi1/0/3"), rules));
    }

    [Fact]
    public void Include_pattern_limits_monitoring_to_matches()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { IncludePattern = "*uplink*" };
        Assert.True(InterfaceMonitor.FollowsRules(Port("Gi0/0", "Uplink to core"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi0/2", "printer"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/1"), rules));
    }

    [Fact]
    public void Exclude_wins_when_a_port_matches_both_patterns()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { IncludePattern = "Gi1/0/*", ExcludePattern = "Gi1/0/1" };
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/1"), rules));
        Assert.True(InterfaceMonitor.FollowsRules(Port("Gi1/0/2"), rules));
    }

    [Fact]
    public void Semicolon_separates_alternatives_and_fields_can_be_limited()
    {
        var rules = InterfaceMonitorRules.MonitorAll with
        {
            ExcludePattern = "Gi1/0/*;Te*",
            MatchName = true,
            MatchDescr = false,
            MatchAlias = false
        };
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/8", descr: "ignored"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Te1/1", descr: "uplink"), rules));
        Assert.True(InterfaceMonitor.FollowsRules(new InterfaceIdentity("Gi0/1", "Gi1/0/1", "uplink", 1), rules));
    }

    [Fact]
    public void Admin_down_and_missing_alias_can_be_excluded()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { ExcludeAdminDown = true, RequireAlias = true };
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi0/1", "uplink", admin: 2), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi0/1"), rules));
        Assert.True(InterfaceMonitor.FollowsRules(Port("Gi0/1", "uplink"), rules));
    }

    [Fact]
    public void Manual_override_wins_over_include_and_exclude()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { ExcludePattern = "Gi1/0/*", IncludePattern = "*uplink*" };
        var access = Port("Gi1/0/4");
        var uplink = Port("Gi0/0", "uplink");
        Assert.True(InterfaceMonitor.Evaluate(access, rules, true));
        Assert.False(InterfaceMonitor.Evaluate(uplink, rules, false));
        Assert.False(InterfaceMonitor.Evaluate(access, rules, null));
        Assert.True(InterfaceMonitor.Evaluate(uplink, rules, null));
    }

    [Fact]
    public void Regex_include_is_case_insensitive_and_a_broken_pattern_is_rejected()
    {
        var rules = InterfaceMonitorRules.MonitorAll with
        {
            Syntax = InterfacePatternSyntax.Regex,
            IncludePattern = @"^Gi0/\d+$",
            MatchAlias = false
        };
        Assert.Null(InterfaceMonitor.Validate(rules));
        Assert.True(InterfaceMonitor.FollowsRules(Port("gi0/1"), rules));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi1/0/1"), rules));

        var broken = rules with { IncludePattern = "[" };
        Assert.Contains("Invalid regular expression", InterfaceMonitor.Validate(broken));
        Assert.False(InterfaceMonitor.FollowsRules(Port("Gi0/1"), broken));
    }

    [Fact]
    public void Trap_policy_suppresses_unmonitored_ports_and_alerts_monitored_ones()
    {
        Assert.Equal(InterfaceTrapEffect.None, InterfaceTrapPolicy.Decide(null, false));
        Assert.Equal(InterfaceTrapEffect.None, InterfaceTrapPolicy.Decide("down", null));
        Assert.Equal(InterfaceTrapEffect.Suppress, InterfaceTrapPolicy.Decide("down", false));
        Assert.Equal(InterfaceTrapEffect.Suppress, InterfaceTrapPolicy.Decide("up", false));
        Assert.Equal(InterfaceTrapEffect.OpenDown, InterfaceTrapPolicy.Decide("down", true));
        Assert.Equal(InterfaceTrapEffect.ResolveDown, InterfaceTrapPolicy.Decide("up", true));
    }
}
