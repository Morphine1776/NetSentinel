using System.Text.Json;
using NetSentinel.Core;
using NetSentinel.Services;

namespace NetSentinel.Tests;

public class PolicyResolutionTests
{
    [Fact]
    public void Most_specific_explicit_value_wins_and_nulls_inherit()
    {
        var global = PolicyValues.BuiltInDefaults();
        global.Community = "public";
        global.Port = 161;
        global.TimeoutMs = 2000;
        global.V3AuthSecret = "";
        var location = new PolicyValues { Community = "site-ro", TimeoutMs = 1500, V3AuthSecret = "location-secret" };
        var device = new PolicyValues { Port = 1161 };

        var resolved = PolicyResolver.Resolve(global, location, device, "FMC");

        Assert.Equal("site-ro", resolved.Community.Value);
        Assert.Equal(PolicyScope.Location, resolved.Community.Scope);
        Assert.Equal("FMC", resolved.Community.Source);
        Assert.Equal(1161, resolved.Port.Value);
        Assert.Equal(PolicyScope.Device, resolved.Port.Scope);
        Assert.Equal(1500, resolved.TimeoutMs.Value);
        Assert.Equal(PolicyScope.Location, resolved.TimeoutMs.Scope);
        Assert.Equal(SnmpVersion.V2C, resolved.Version.Value);
        Assert.Equal(PolicyScope.Global, resolved.Version.Scope);
        Assert.Equal("Global", resolved.Version.Source);
        Assert.Equal("location-secret", resolved.V3AuthSecret.Value);
        Assert.Equal(PolicyScope.Location, resolved.V3AuthSecret.Scope);
        Assert.Equal("inherited", PolicyResolver.SecretState(device.V3AuthSecret));
        Assert.Equal("set", PolicyResolver.SecretState(location.V3AuthSecret));
    }

    [Fact]
    public void Device_secret_override_is_used_by_the_poller_and_hidden_from_the_api_shape()
    {
        var global = PolicyValues.BuiltInDefaults();
        var device = new PolicyValues { V3AuthSecret = "device-secret-value" };
        var resolved = PolicyResolver.Resolve(global, new PolicyValues(), device, "FMC");

        Assert.Equal("device-secret-value", resolved.V3AuthSecret.Value);
        Assert.Equal(PolicyScope.Device, resolved.V3AuthSecret.Scope);
        Assert.Equal("set", PolicyResolver.SecretState(device.V3AuthSecret));
        Assert.Equal("inherited", PolicyResolver.SecretState(device.V3PrivSecret));

        var json = JsonSerializer.Serialize(PolicyStore.LayerJson(device, resolved));
        Assert.DoesNotContain("device-secret-value", json, StringComparison.Ordinal);
        Assert.Contains("\"state\":\"set\"", json, StringComparison.Ordinal);
        Assert.Contains("\"state\":\"inherited\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Standing_unmonitor_down_loses_to_a_manual_checkbox()
    {
        var rules = InterfaceMonitorRules.MonitorAll with { UnmonitorDown = true };
        var down = new InterfaceIdentity("Gi1/0/2", "Gi1/0/2", "", 1, 2);
        var adminDown = new InterfaceIdentity("Gi1/0/24", "Gi1/0/24", "", 2, 2);
        var up = new InterfaceIdentity("Gi0/1", "Gi0/1", "uplink", 1, 1);

        Assert.False(InterfaceMonitor.Evaluate(down, rules, null));
        Assert.False(InterfaceMonitor.Evaluate(adminDown, rules, null));
        Assert.True(InterfaceMonitor.Evaluate(up, rules, null));
        Assert.True(InterfaceMonitor.Evaluate(down, rules, true));
        Assert.False(InterfaceMonitor.Evaluate(up, rules, false));
    }
}
