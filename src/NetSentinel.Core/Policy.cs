namespace NetSentinel.Core;

public enum PolicyScope
{
    Global,
    Location,
    Device
}

/// <summary>
/// One layer of SNMP and interface-monitoring settings. A null property inherits from the broader layer.
/// </summary>
public sealed class PolicyValues
{
    public SnmpVersion? Version { get; set; }
    public string? Community { get; set; }
    public string? V3User { get; set; }
    public string? V3AuthProtocol { get; set; }
    public string? V3AuthSecret { get; set; }
    public string? V3PrivProtocol { get; set; }
    public string? V3PrivSecret { get; set; }
    public int? Port { get; set; }
    public int? PollIntervalSeconds { get; set; }
    public int? TimeoutMs { get; set; }
    public int? Retries { get; set; }
    public string? IfIncludePattern { get; set; }
    public string? IfExcludePattern { get; set; }
    public string? IfPatternSyntax { get; set; }
    public string? IfMatchFields { get; set; }
    public bool? ExcludeAdminDown { get; set; }
    public bool? RequireAlias { get; set; }
    public bool? UnmonitorDown { get; set; }
    public bool? AlertOnHaChange { get; set; }

    public static PolicyValues BuiltInDefaults() => new()
    {
        Version = SnmpVersion.V2C,
        Community = "public",
        V3User = "",
        V3AuthProtocol = "None",
        V3AuthSecret = "",
        V3PrivProtocol = "None",
        V3PrivSecret = "",
        Port = 161,
        PollIntervalSeconds = 60,
        TimeoutMs = 2000,
        Retries = 1,
        IfIncludePattern = "",
        IfExcludePattern = "",
        IfPatternSyntax = "glob",
        IfMatchFields = "name,descr,alias",
        ExcludeAdminDown = false,
        RequireAlias = false,
        UnmonitorDown = false,
        AlertOnHaChange = true
    };
}

public sealed record ResolvedValue<T>(T Value, PolicyScope Scope, string Source);

public sealed class ResolvedPolicy
{
    public ResolvedValue<SnmpVersion> Version { get; init; } = null!;
    public ResolvedValue<string> Community { get; init; } = null!;
    public ResolvedValue<string> V3User { get; init; } = null!;
    public ResolvedValue<string> V3AuthProtocol { get; init; } = null!;
    public ResolvedValue<string> V3AuthSecret { get; init; } = null!;
    public ResolvedValue<string> V3PrivProtocol { get; init; } = null!;
    public ResolvedValue<string> V3PrivSecret { get; init; } = null!;
    public ResolvedValue<int> Port { get; init; } = null!;
    public ResolvedValue<int> PollIntervalSeconds { get; init; } = null!;
    public ResolvedValue<int> TimeoutMs { get; init; } = null!;
    public ResolvedValue<int> Retries { get; init; } = null!;
    public ResolvedValue<string> IfIncludePattern { get; init; } = null!;
    public ResolvedValue<string> IfExcludePattern { get; init; } = null!;
    public ResolvedValue<string> IfPatternSyntax { get; init; } = null!;
    public ResolvedValue<string> IfMatchFields { get; init; } = null!;
    public ResolvedValue<bool> ExcludeAdminDown { get; init; } = null!;
    public ResolvedValue<bool> RequireAlias { get; init; } = null!;
    public ResolvedValue<bool> UnmonitorDown { get; init; } = null!;
    public ResolvedValue<bool> AlertOnHaChange { get; init; } = null!;

    public InterfaceMonitorRules InterfaceRules()
    {
        if (!InterfaceMonitor.TrySyntax(IfPatternSyntax.Value, out var syntax))
        {
            syntax = InterfacePatternSyntax.Glob;
        }

        if (!InterfaceMonitor.TryParseFields(IfMatchFields.Value, out var name, out var descr, out var alias))
        {
            name = true;
            descr = true;
            alias = true;
        }

        return new InterfaceMonitorRules(
            IfIncludePattern.Value ?? "",
            IfExcludePattern.Value ?? "",
            syntax,
            name,
            descr,
            alias,
            ExcludeAdminDown.Value,
            RequireAlias.Value,
            UnmonitorDown.Value);
    }
}

public static class PolicyResolver
{
    public static ResolvedPolicy Resolve(PolicyValues? global, PolicyValues? location, PolicyValues? device, string? locationName)
    {
        var fallback = PolicyValues.BuiltInDefaults();
        var root = global ?? fallback;
        var place = string.IsNullOrWhiteSpace(locationName) ? "Global" : locationName.Trim();

        return new ResolvedPolicy
        {
            Version = Pick(device?.Version, location?.Version, root.Version ?? fallback.Version!.Value, place),
            Community = Pick(device?.Community, location?.Community, root.Community ?? fallback.Community!, place),
            V3User = Pick(device?.V3User, location?.V3User, root.V3User ?? fallback.V3User!, place),
            V3AuthProtocol = Pick(device?.V3AuthProtocol, location?.V3AuthProtocol, root.V3AuthProtocol ?? fallback.V3AuthProtocol!, place),
            V3AuthSecret = Pick(device?.V3AuthSecret, location?.V3AuthSecret, root.V3AuthSecret ?? fallback.V3AuthSecret!, place),
            V3PrivProtocol = Pick(device?.V3PrivProtocol, location?.V3PrivProtocol, root.V3PrivProtocol ?? fallback.V3PrivProtocol!, place),
            V3PrivSecret = Pick(device?.V3PrivSecret, location?.V3PrivSecret, root.V3PrivSecret ?? fallback.V3PrivSecret!, place),
            Port = Pick(device?.Port, location?.Port, (root.Port ?? fallback.Port)!.Value, place),
            PollIntervalSeconds = Pick(device?.PollIntervalSeconds, location?.PollIntervalSeconds, (root.PollIntervalSeconds ?? fallback.PollIntervalSeconds)!.Value, place),
            TimeoutMs = Pick(device?.TimeoutMs, location?.TimeoutMs, (root.TimeoutMs ?? fallback.TimeoutMs)!.Value, place),
            Retries = Pick(device?.Retries, location?.Retries, (root.Retries ?? fallback.Retries)!.Value, place),
            IfIncludePattern = Pick(device?.IfIncludePattern, location?.IfIncludePattern, root.IfIncludePattern ?? fallback.IfIncludePattern!, place),
            IfExcludePattern = Pick(device?.IfExcludePattern, location?.IfExcludePattern, root.IfExcludePattern ?? fallback.IfExcludePattern!, place),
            IfPatternSyntax = Pick(device?.IfPatternSyntax, location?.IfPatternSyntax, root.IfPatternSyntax ?? fallback.IfPatternSyntax!, place),
            IfMatchFields = Pick(device?.IfMatchFields, location?.IfMatchFields, root.IfMatchFields ?? fallback.IfMatchFields!, place),
            ExcludeAdminDown = Pick(device?.ExcludeAdminDown, location?.ExcludeAdminDown, (root.ExcludeAdminDown ?? fallback.ExcludeAdminDown)!.Value, place),
            RequireAlias = Pick(device?.RequireAlias, location?.RequireAlias, (root.RequireAlias ?? fallback.RequireAlias)!.Value, place),
            UnmonitorDown = Pick(device?.UnmonitorDown, location?.UnmonitorDown, (root.UnmonitorDown ?? fallback.UnmonitorDown)!.Value, place),
            AlertOnHaChange = Pick(device?.AlertOnHaChange, location?.AlertOnHaChange, (root.AlertOnHaChange ?? fallback.AlertOnHaChange)!.Value, place)
        };
    }

    public static string SourcePhrase(ResolvedValue<object?> field)
        => field.Scope == PolicyScope.Device ? "on this device" : "from " + field.Source;

    public static string SecretState(string? storedAtThisLevel)
        => storedAtThisLevel is null ? "inherited" : "set";

    private static ResolvedValue<T> Pick<T>(T? device, T? location, T global, string locationName) where T : struct
    {
        if (device is not null)
        {
            return new ResolvedValue<T>(device.Value, PolicyScope.Device, "Device");
        }

        if (location is not null)
        {
            return new ResolvedValue<T>(location.Value, PolicyScope.Location, locationName);
        }

        return new ResolvedValue<T>(global, PolicyScope.Global, "Global");
    }

    private static ResolvedValue<string> Pick(string? device, string? location, string global, string locationName)
    {
        if (device is not null)
        {
            return new ResolvedValue<string>(device, PolicyScope.Device, "Device");
        }

        if (location is not null)
        {
            return new ResolvedValue<string>(location, PolicyScope.Location, locationName);
        }

        return new ResolvedValue<string>(global, PolicyScope.Global, "Global");
    }
}
