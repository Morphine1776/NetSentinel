using System.Text.Json;
using NetSentinel.Core;
using NetSentinel.Data;
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

    [Fact]
    public void A_new_device_form_inherits_every_policy_field()
    {
        var global = PolicyValues.BuiltInDefaults();
        global.IfIncludePattern = "*uplink*";
        global.IfExcludePattern = "vlan.*;ae2.*";
        global.IfPatternSyntax = "glob";
        global.ExcludeAdminDown = true;
        var inherited = PolicyResolver.Resolve(global, null, new PolicyValues(), "Global");
        var form = PolicyStore.FormFrom(new PolicyValues(), inherited);

        Assert.False(form.UseVersion);
        Assert.False(form.UseCommunity);
        Assert.False(form.UsePort);
        Assert.False(form.UsePollInterval);
        Assert.False(form.UseTimeout);
        Assert.False(form.UseIfInclude);
        Assert.False(form.UseIfExclude);
        Assert.False(form.UseIfSyntax);
        Assert.False(form.UseExcludeAdminDown);
        Assert.False(form.UseUnmonitorDown);
        Assert.False(form.UseAlertOnHaChange);
        Assert.Equal("*uplink*", form.IfInclude);
        Assert.Equal("vlan.*;ae2.*", form.IfExclude);

        var written = PolicyStore.ApplyForm(new PolicyValues(), form, inheritAllowed: true);
        Assert.Null(written.Version);
        Assert.Null(written.Community);
        Assert.Null(written.Port);
        Assert.Null(written.IfIncludePattern);
        Assert.Null(written.IfExcludePattern);
        Assert.Null(written.ExcludeAdminDown);
        Assert.Null(written.UnmonitorDown);
    }

    [Fact]
    public void Only_a_changed_field_is_stored_and_copies_of_inherited_values_are_cleared()
    {
        var global = PolicyValues.BuiltInDefaults();
        global.Community = "public";
        global.IfIncludePattern = "*uplink*";
        global.Port = 161;
        var inherited = PolicyResolver.Resolve(global, null, null, "Global");
        var form = PolicyStore.FormFrom(new PolicyValues(), inherited);
        form.UseCommunity = true;
        form.Community = "secret-ro";
        form.UseIfInclude = true;
        form.IfInclude = "*uplink*";
        form.UsePort = true;
        form.Port = 161;

        var written = PolicyStore.DropMatches(PolicyStore.ApplyForm(new PolicyValues(), form, inheritAllowed: true), inherited);

        Assert.Equal("secret-ro", written.Community);
        Assert.Null(written.IfIncludePattern);
        Assert.Null(written.Port);
        Assert.Null(written.Version);
    }

    [Fact]
    public void Blank_csv_inherits_and_a_repeated_host_is_a_warning_not_an_error()
    {
        const string csv = "name,host\nNew firewall,10.184.254.3\n";
        var preview = CsvDevices.Preview(csv, new[] { new ExistingDeviceRef(4, "CGH-PA3440-1", "10.184.254.3", 161, null) });
        var row = Assert.Single(preview.Rows);
        Assert.Equal(CsvRowStatus.Duplicate, row.Status);
        Assert.NotNull(row.Warning);
        Assert.Contains("10.184.254.3", row.Warning, StringComparison.Ordinal);
        Assert.Empty(row.Errors);
    }

    [Fact]
    public void The_board_shows_one_row_and_an_explicit_na_badge_when_ha_is_unknown()
    {
        var now = DateTime.UtcNow;
        var device = new Device
        {
            Id = 7,
            Name = "CGH-PA3440-1",
            Host = "10.184.254.3",
            Location = "CGH",
            Enabled = true,
            LastPollAt = now,
            LastSnmpOk = true,
            Port = 161
        };

        var board = DeviceBoardBuilder.Build(new[] { device }, new HashSet<int>());
        var row = Assert.Single(Assert.Single(board.Groups).Devices);
        Assert.Equal("CGH-PA3440-1", row.Name);
        Assert.Equal("N/A", row.HaLabel);
        Assert.Equal("ha-na", row.HaClass);
    }
}
