using Microsoft.EntityFrameworkCore;
using NetSentinel;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class PolicyForm
{
    public bool UseVersion { get; set; }
    public string Version { get; set; } = "V2C";
    public bool UseCommunity { get; set; }
    public string? Community { get; set; }
    public bool UseV3User { get; set; }
    public string? V3User { get; set; }
    public bool UseV3AuthProtocol { get; set; }
    public string V3AuthProtocol { get; set; } = "None";
    public bool UseV3AuthSecret { get; set; }
    public string? V3AuthSecret { get; set; }
    public bool UseV3PrivProtocol { get; set; }
    public string V3PrivProtocol { get; set; } = "None";
    public bool UseV3PrivSecret { get; set; }
    public string? V3PrivSecret { get; set; }
    public bool UsePort { get; set; }
    public int? Port { get; set; }
    public bool UsePollInterval { get; set; }
    public int? PollIntervalSeconds { get; set; }
    public bool UseTimeout { get; set; }
    public int? TimeoutMs { get; set; }
    public bool UseRetries { get; set; }
    public int? Retries { get; set; }
    public bool UseIfInclude { get; set; }
    public string? IfInclude { get; set; }
    public bool UseIfExclude { get; set; }
    public string? IfExclude { get; set; }
    public bool UseIfSyntax { get; set; }
    public string IfSyntax { get; set; } = "glob";
    public bool UseIfMatch { get; set; }
    public bool MatchName { get; set; } = true;
    public bool MatchDescr { get; set; } = true;
    public bool MatchAlias { get; set; } = true;
    public bool UseExcludeAdminDown { get; set; }
    public bool ExcludeAdminDown { get; set; }
    public bool UseRequireAlias { get; set; }
    public bool RequireAlias { get; set; }
    public bool UseUnmonitorDown { get; set; }
    public bool UnmonitorDown { get; set; }
    public bool UseAlertOnHaChange { get; set; }
    public bool AlertOnHaChange { get; set; } = true;
}

public sealed class PolicyCatalog
{
    private readonly PolicyValues _global;
    private readonly Dictionary<string, (string Display, PolicyValues Values)> _locations;

    public PolicyCatalog(PolicyValues global, IReadOnlyDictionary<string, (string Display, PolicyValues Values)> locations)
    {
        _global = global;
        _locations = new Dictionary<string, (string, PolicyValues)>(locations, StringComparer.Ordinal);
    }

    public PolicyValues Global => _global;

    public IReadOnlyList<(string Key, string Display, PolicyValues Values)> Locations
        => _locations.Select(item => (item.Key, item.Value.Display, item.Value.Values))
            .OrderBy(item => item.Display, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public bool TryLocation(string? key, out string display, out PolicyValues values)
    {
        var normalized = LocationGroups.KeyFor(key);
        if (string.Equals(key, "unassigned", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "";
        }

        if (_locations.TryGetValue(normalized, out var found))
        {
            display = found.Display;
            values = found.Values;
            return true;
        }

        display = normalized.Length == 0 ? LocationGroups.UnassignedName : normalized;
        values = new PolicyValues();
        return false;
    }

    public ResolvedPolicy Resolve(Device device)
    {
        var key = LocationGroups.KeyFor(device.Location);
        _locations.TryGetValue(key, out var location);
        var name = location.Display;
        if (string.IsNullOrWhiteSpace(name))
        {
            name = key.Length == 0 ? LocationGroups.UnassignedName : (device.Location ?? "").Trim();
        }

        return PolicyResolver.Resolve(_global, location.Values, PolicyStore.FromDevice(device), name);
    }

    public string LocationName(Device device)
    {
        var key = LocationGroups.KeyFor(device.Location);
        if (_locations.TryGetValue(key, out var location) && !string.IsNullOrWhiteSpace(location.Display))
        {
            return location.Display;
        }

        return key.Length == 0 ? LocationGroups.UnassignedName : (device.Location ?? "").Trim();
    }
}

public static class PolicyStore
{
    public static async Task EnsureSeedAsync(AppDbContext db, IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var global = await db.Policies.FirstOrDefaultAsync(policy => policy.Scope == "global", cancellationToken);
        if (global is null)
        {
            var seeded = PolicyValues.BuiltInDefaults();
            seeded.TimeoutMs = Math.Clamp(configuration.GetValue("Snmp:TimeoutMs", 2000), 200, 30_000);
            seeded.Retries = Math.Clamp(configuration.GetValue("Snmp:Retries", 1), 0, 5);
            global = new MonitorPolicy { Scope = "global", LocationKey = "", DisplayName = "Global" };
            WritePolicy(global, seeded);
            db.Policies.Add(global);
        }

        await EnsureLocationsAsync(db, cancellationToken);
    }

    public static async Task EnsureLocationsAsync(AppDbContext db, CancellationToken cancellationToken = default)
    {
        var locations = await db.Devices.AsNoTracking().Select(device => device.Location).ToListAsync(cancellationToken);
        var existing = await db.Policies.Where(policy => policy.Scope == "location").Select(policy => policy.LocationKey).ToListAsync(cancellationToken);
        var known = existing.ToHashSet(StringComparer.Ordinal);
        foreach (var group in locations.GroupBy(LocationGroups.KeyFor))
        {
            if (!known.Add(group.Key))
            {
                continue;
            }

            db.Policies.Add(new MonitorPolicy
            {
                Scope = "location",
                LocationKey = group.Key,
                DisplayName = DisplayName(group.Key, group)
            });
        }
    }

    public static async Task EnsureLocationAsync(AppDbContext db, string? location, CancellationToken cancellationToken = default)
    {
        var key = LocationGroups.KeyFor(location);
        var exists = await db.Policies.AnyAsync(policy => policy.Scope == "location" && policy.LocationKey == key, cancellationToken);
        if (exists)
        {
            return;
        }

        db.Policies.Add(new MonitorPolicy
        {
            Scope = "location",
            LocationKey = key,
            DisplayName = key.Length == 0 ? LocationGroups.UnassignedName : (location ?? "").Trim()
        });
    }

    public static async Task<PolicyCatalog> LoadAsync(AppDbContext db, CancellationToken cancellationToken = default)
    {
        var rows = await db.Policies.AsNoTracking().ToListAsync(cancellationToken);
        var globalRow = rows.FirstOrDefault(policy => policy.Scope == "global");
        var global = globalRow is null ? PolicyValues.BuiltInDefaults() : FromPolicy(globalRow);
        var locations = new Dictionary<string, (string Display, PolicyValues Values)>(StringComparer.Ordinal);
        foreach (var row in rows.Where(policy => policy.Scope == "location"))
        {
            locations[row.LocationKey] = (row.DisplayName, FromPolicy(row));
        }

        return new PolicyCatalog(global, locations);
    }

    public static PolicyValues FromDevice(Device device) => new()
    {
        Version = device.Version,
        Community = device.Community,
        V3User = device.V3User,
        V3AuthProtocol = device.V3AuthProtocol,
        V3AuthSecret = device.V3AuthPassword,
        V3PrivProtocol = device.V3PrivProtocol,
        V3PrivSecret = device.V3PrivPassword,
        Port = device.Port,
        PollIntervalSeconds = device.PollIntervalSeconds,
        TimeoutMs = device.TimeoutMs,
        Retries = device.Retries,
        IfIncludePattern = device.IfIncludePattern,
        IfExcludePattern = device.IfExcludePattern,
        IfPatternSyntax = device.IfPatternSyntax,
        IfMatchFields = device.IfMatchFields,
        ExcludeAdminDown = device.IfExcludeAdminDown,
        RequireAlias = device.IfRequireAlias,
        UnmonitorDown = device.UnmonitorDown,
        AlertOnHaChange = device.AlertOnHaChange
    };

    public static PolicyValues FromPolicy(MonitorPolicy policy) => new()
    {
        Version = policy.SnmpVersion is int version ? (SnmpVersion)version : null,
        Community = policy.Community,
        V3User = policy.V3User,
        V3AuthProtocol = policy.V3AuthProtocol,
        V3AuthSecret = policy.V3AuthSecret,
        V3PrivProtocol = policy.V3PrivProtocol,
        V3PrivSecret = policy.V3PrivSecret,
        Port = policy.Port,
        PollIntervalSeconds = policy.PollIntervalSeconds,
        TimeoutMs = policy.TimeoutMs,
        Retries = policy.Retries,
        IfIncludePattern = policy.IfIncludePattern,
        IfExcludePattern = policy.IfExcludePattern,
        IfPatternSyntax = policy.IfPatternSyntax,
        IfMatchFields = policy.IfMatchFields,
        ExcludeAdminDown = policy.IfExcludeAdminDown,
        RequireAlias = policy.IfRequireAlias,
        UnmonitorDown = policy.UnmonitorDown,
        AlertOnHaChange = policy.AlertOnHaChange
    };

    public static void WriteDevice(Device device, PolicyValues values)
    {
        device.Version = values.Version;
        device.Community = values.Community;
        device.V3User = values.V3User;
        device.V3AuthProtocol = values.V3AuthProtocol;
        device.V3AuthPassword = values.V3AuthSecret;
        device.V3PrivProtocol = values.V3PrivProtocol;
        device.V3PrivPassword = values.V3PrivSecret;
        device.Port = values.Port;
        device.PollIntervalSeconds = values.PollIntervalSeconds;
        device.TimeoutMs = values.TimeoutMs;
        device.Retries = values.Retries;
        device.IfIncludePattern = values.IfIncludePattern;
        device.IfExcludePattern = values.IfExcludePattern;
        device.IfPatternSyntax = values.IfPatternSyntax;
        device.IfMatchFields = values.IfMatchFields;
        device.IfExcludeAdminDown = values.ExcludeAdminDown;
        device.IfRequireAlias = values.RequireAlias;
        device.UnmonitorDown = values.UnmonitorDown;
        device.AlertOnHaChange = values.AlertOnHaChange;
    }

    public static void WritePolicy(MonitorPolicy policy, PolicyValues values)
    {
        policy.SnmpVersion = values.Version is SnmpVersion version ? (int)version : null;
        policy.Community = values.Community;
        policy.V3User = values.V3User;
        policy.V3AuthProtocol = values.V3AuthProtocol;
        policy.V3AuthSecret = values.V3AuthSecret;
        policy.V3PrivProtocol = values.V3PrivProtocol;
        policy.V3PrivSecret = values.V3PrivSecret;
        policy.Port = values.Port;
        policy.PollIntervalSeconds = values.PollIntervalSeconds;
        policy.TimeoutMs = values.TimeoutMs;
        policy.Retries = values.Retries;
        policy.IfIncludePattern = values.IfIncludePattern;
        policy.IfExcludePattern = values.IfExcludePattern;
        policy.IfPatternSyntax = values.IfPatternSyntax;
        policy.IfMatchFields = values.IfMatchFields;
        policy.IfExcludeAdminDown = values.ExcludeAdminDown;
        policy.IfRequireAlias = values.RequireAlias;
        policy.UnmonitorDown = values.UnmonitorDown;
        policy.AlertOnHaChange = values.AlertOnHaChange;
    }

    public static PolicyForm FormFrom(PolicyValues values, ResolvedPolicy effective)
    {
        return new PolicyForm
        {
            UseVersion = values.Version is not null,
            Version = TextFormat.VersionToken(values.Version ?? effective.Version.Value),
            UseCommunity = values.Community is not null,
            Community = values.Community ?? effective.Community.Value,
            UseV3User = values.V3User is not null,
            V3User = values.V3User ?? effective.V3User.Value,
            UseV3AuthProtocol = values.V3AuthProtocol is not null,
            V3AuthProtocol = NormalizeProtocol(values.V3AuthProtocol ?? effective.V3AuthProtocol.Value, "None"),
            UseV3AuthSecret = values.V3AuthSecret is not null,
            UseV3PrivProtocol = values.V3PrivProtocol is not null,
            V3PrivProtocol = NormalizeProtocol(values.V3PrivProtocol ?? effective.V3PrivProtocol.Value, "None"),
            UseV3PrivSecret = values.V3PrivSecret is not null,
            UsePort = values.Port is not null,
            Port = values.Port ?? effective.Port.Value,
            UsePollInterval = values.PollIntervalSeconds is not null,
            PollIntervalSeconds = values.PollIntervalSeconds ?? effective.PollIntervalSeconds.Value,
            UseTimeout = values.TimeoutMs is not null,
            TimeoutMs = values.TimeoutMs ?? effective.TimeoutMs.Value,
            UseRetries = values.Retries is not null,
            Retries = values.Retries ?? effective.Retries.Value,
            UseIfInclude = values.IfIncludePattern is not null,
            IfInclude = values.IfIncludePattern ?? effective.IfIncludePattern.Value,
            UseIfExclude = values.IfExcludePattern is not null,
            IfExclude = values.IfExcludePattern ?? effective.IfExcludePattern.Value,
            UseIfSyntax = values.IfPatternSyntax is not null,
            IfSyntax = values.IfPatternSyntax ?? effective.IfPatternSyntax.Value,
            UseIfMatch = values.IfMatchFields is not null,
            MatchName = Fields(values.IfMatchFields ?? effective.IfMatchFields.Value).Name,
            MatchDescr = Fields(values.IfMatchFields ?? effective.IfMatchFields.Value).Descr,
            MatchAlias = Fields(values.IfMatchFields ?? effective.IfMatchFields.Value).Alias,
            UseExcludeAdminDown = values.ExcludeAdminDown is not null,
            ExcludeAdminDown = values.ExcludeAdminDown ?? effective.ExcludeAdminDown.Value,
            UseRequireAlias = values.RequireAlias is not null,
            RequireAlias = values.RequireAlias ?? effective.RequireAlias.Value,
            UseUnmonitorDown = values.UnmonitorDown is not null,
            UnmonitorDown = values.UnmonitorDown ?? effective.UnmonitorDown.Value,
            UseAlertOnHaChange = values.AlertOnHaChange is not null,
            AlertOnHaChange = values.AlertOnHaChange ?? effective.AlertOnHaChange.Value
        };
    }

    public static PolicyValues ApplyForm(PolicyValues current, PolicyForm form, bool inheritAllowed)
    {
        var next = new PolicyValues();
        if (!inheritAllowed)
        {
            form.UseVersion = form.UseCommunity = form.UseV3User = form.UseV3AuthProtocol = form.UseV3PrivProtocol = true;
            form.UsePort = form.UsePollInterval = form.UseTimeout = form.UseRetries = true;
            form.UseIfInclude = form.UseIfExclude = form.UseIfSyntax = form.UseIfMatch = true;
            form.UseExcludeAdminDown = form.UseRequireAlias = form.UseUnmonitorDown = form.UseAlertOnHaChange = true;
            form.UseV3AuthSecret = true;
            form.UseV3PrivSecret = true;
        }

        next.Version = form.UseVersion && TryVersion(form.Version, out var version) ? version : form.UseVersion ? current.Version : null;
        next.Community = form.UseCommunity ? (form.Community ?? "").Trim() : null;
        next.V3User = form.UseV3User ? (form.V3User ?? "").Trim() : null;
        next.V3AuthProtocol = form.UseV3AuthProtocol ? NormalizeProtocol(form.V3AuthProtocol, "None") : null;
        next.V3PrivProtocol = form.UseV3PrivProtocol ? NormalizeProtocol(form.V3PrivProtocol, "None") : null;
        next.V3AuthSecret = Secret(form.UseV3AuthSecret, form.V3AuthSecret, current.V3AuthSecret);
        next.V3PrivSecret = Secret(form.UseV3PrivSecret, form.V3PrivSecret, current.V3PrivSecret);
        next.Port = form.UsePort ? form.Port : null;
        next.PollIntervalSeconds = form.UsePollInterval ? form.PollIntervalSeconds : null;
        next.TimeoutMs = form.UseTimeout ? form.TimeoutMs : null;
        next.Retries = form.UseRetries ? form.Retries : null;
        next.IfIncludePattern = form.UseIfInclude ? (form.IfInclude ?? "").Trim() : null;
        next.IfExcludePattern = form.UseIfExclude ? (form.IfExclude ?? "").Trim() : null;
        next.IfPatternSyntax = form.UseIfSyntax ? (InterfaceMonitor.TrySyntax(form.IfSyntax, out var syntax) ? InterfaceMonitor.FormatSyntax(syntax) : form.IfSyntax) : null;
        next.IfMatchFields = form.UseIfMatch ? InterfaceMonitor.FormatFields(form.MatchName, form.MatchDescr, form.MatchAlias) : null;
        next.ExcludeAdminDown = form.UseExcludeAdminDown ? form.ExcludeAdminDown : null;
        next.RequireAlias = form.UseRequireAlias ? form.RequireAlias : null;
        next.UnmonitorDown = form.UseUnmonitorDown ? form.UnmonitorDown : null;
        next.AlertOnHaChange = form.UseAlertOnHaChange ? form.AlertOnHaChange : null;
        return next;
    }

    public static PolicyValues DropMatches(PolicyValues written, ResolvedPolicy inherited)
    {
        ArgumentNullException.ThrowIfNull(written);
        ArgumentNullException.ThrowIfNull(inherited);
        if (written.Version is SnmpVersion version && version == inherited.Version.Value)
        {
            written.Version = null;
        }

        if (Same(written.Community, inherited.Community.Value)) written.Community = null;
        if (Same(written.V3User, inherited.V3User.Value)) written.V3User = null;
        if (Same(written.V3AuthProtocol, inherited.V3AuthProtocol.Value)) written.V3AuthProtocol = null;
        if (Same(written.V3AuthSecret, inherited.V3AuthSecret.Value)) written.V3AuthSecret = null;
        if (Same(written.V3PrivProtocol, inherited.V3PrivProtocol.Value)) written.V3PrivProtocol = null;
        if (Same(written.V3PrivSecret, inherited.V3PrivSecret.Value)) written.V3PrivSecret = null;
        if (written.Port is int port && port == inherited.Port.Value) written.Port = null;
        if (written.PollIntervalSeconds is int interval && interval == inherited.PollIntervalSeconds.Value) written.PollIntervalSeconds = null;
        if (written.TimeoutMs is int timeout && timeout == inherited.TimeoutMs.Value) written.TimeoutMs = null;
        if (written.Retries is int retries && retries == inherited.Retries.Value) written.Retries = null;
        if (Same(written.IfIncludePattern, inherited.IfIncludePattern.Value)) written.IfIncludePattern = null;
        if (Same(written.IfExcludePattern, inherited.IfExcludePattern.Value)) written.IfExcludePattern = null;
        if (Same(written.IfPatternSyntax, inherited.IfPatternSyntax.Value)) written.IfPatternSyntax = null;
        if (Same(written.IfMatchFields, inherited.IfMatchFields.Value)) written.IfMatchFields = null;
        if (written.ExcludeAdminDown is bool admin && admin == inherited.ExcludeAdminDown.Value) written.ExcludeAdminDown = null;
        if (written.RequireAlias is bool alias && alias == inherited.RequireAlias.Value) written.RequireAlias = null;
        if (written.UnmonitorDown is bool down && down == inherited.UnmonitorDown.Value) written.UnmonitorDown = null;
        if (written.AlertOnHaChange is bool alert && alert == inherited.AlertOnHaChange.Value) written.AlertOnHaChange = null;
        return written;
    }

    private static bool Same(string? written, string? inherited)
        => written is not null && string.Equals(written.Trim(), (inherited ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

    public static List<string> Validate(ResolvedPolicy policy, PolicyValues written, bool requireConcrete)
    {
        var errors = new List<string>();
        if (requireConcrete)
        {
            if (written.Version is null) errors.Add("Choose an SNMP version.");
            if (written.Port is null) errors.Add("SNMP port is required.");
            if (written.PollIntervalSeconds is null) errors.Add("Poll interval is required.");
            if (written.TimeoutMs is null) errors.Add("Timeout is required.");
            if (written.Retries is null) errors.Add("Retries are required.");
            if (written.Community is null) errors.Add("Community is required.");
        }

        if (policy.Port.Value is < 1 or > 65535)
        {
            errors.Add("SNMP port must be between 1 and 65535.");
        }

        if (policy.PollIntervalSeconds.Value is < 5 or > 86400)
        {
            errors.Add("Poll interval must be between 5 seconds and 24 hours.");
        }

        if (policy.TimeoutMs.Value is < 200 or > 30_000)
        {
            errors.Add("Timeout must be between 200 and 30000 milliseconds.");
        }

        if (policy.Retries.Value is < 0 or > 5)
        {
            errors.Add("Retries must be between 0 and 5.");
        }

        if (written.Version is SnmpVersion version && version is not (SnmpVersion.V1 or SnmpVersion.V2C or SnmpVersion.V3))
        {
            errors.Add("SNMP version must be v1, v2c, or v3.");
        }

        if (policy.Version.Value is SnmpVersion.V1 or SnmpVersion.V2C)
        {
            if (string.IsNullOrWhiteSpace(policy.Community.Value) || policy.Community.Value.Length > 128)
            {
                errors.Add("A community string is required for SNMP v1 and v2c.");
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(policy.V3User.Value) || policy.V3User.Value.Length > 64)
            {
                errors.Add("An SNMPv3 user name is required.");
            }

            var auth = policy.V3AuthProtocol.Value ?? "None";
            var priv = policy.V3PrivProtocol.Value ?? "None";
            if (!IsAuth(auth)) errors.Add("Authentication protocol is not supported.");
            if (!IsPriv(priv)) errors.Add("Privacy protocol is not supported.");
            if (!auth.Equals("None", StringComparison.OrdinalIgnoreCase) && policy.V3AuthSecret.Value.Length < 8)
            {
                errors.Add("SNMPv3 authentication passwords must be at least 8 characters.");
            }

            if (!priv.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                if (auth.Equals("None", StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add("Privacy requires authentication.");
                }

                if (policy.V3PrivSecret.Value.Length < 8)
                {
                    errors.Add("SNMPv3 privacy passwords must be at least 8 characters.");
                }
            }
        }

        var rulesError = InterfaceMonitor.Validate(policy.InterfaceRules());
        if (rulesError is not null)
        {
            errors.Add(rulesError);
        }

        return errors;
    }

    public static object LayerJson(PolicyValues stored, ResolvedPolicy effective)
    {
        return new
        {
            version = Field(stored.Version is null, effective.Version, TextFormat.Version(effective.Version.Value)),
            community = Field(stored.Community is null, effective.Community, effective.Community.Value),
            v3User = Field(stored.V3User is null, effective.V3User, effective.V3User.Value),
            v3AuthProtocol = Field(stored.V3AuthProtocol is null, effective.V3AuthProtocol, effective.V3AuthProtocol.Value),
            v3AuthSecret = SecretField(stored.V3AuthSecret, effective.V3AuthSecret),
            v3PrivProtocol = Field(stored.V3PrivProtocol is null, effective.V3PrivProtocol, effective.V3PrivProtocol.Value),
            v3PrivSecret = SecretField(stored.V3PrivSecret, effective.V3PrivSecret),
            port = Field(stored.Port is null, effective.Port, effective.Port.Value),
            pollIntervalSeconds = Field(stored.PollIntervalSeconds is null, effective.PollIntervalSeconds, effective.PollIntervalSeconds.Value),
            timeoutMs = Field(stored.TimeoutMs is null, effective.TimeoutMs, effective.TimeoutMs.Value),
            retries = Field(stored.Retries is null, effective.Retries, effective.Retries.Value),
            ifInclude = Field(stored.IfIncludePattern is null, effective.IfIncludePattern, effective.IfIncludePattern.Value),
            ifExclude = Field(stored.IfExcludePattern is null, effective.IfExcludePattern, effective.IfExcludePattern.Value),
            ifSyntax = Field(stored.IfPatternSyntax is null, effective.IfPatternSyntax, effective.IfPatternSyntax.Value),
            ifMatch = Field(stored.IfMatchFields is null, effective.IfMatchFields, effective.IfMatchFields.Value),
            excludeAdminDown = Field(stored.ExcludeAdminDown is null, effective.ExcludeAdminDown, effective.ExcludeAdminDown.Value),
            requireAlias = Field(stored.RequireAlias is null, effective.RequireAlias, effective.RequireAlias.Value),
            unmonitorDown = Field(stored.UnmonitorDown is null, effective.UnmonitorDown, effective.UnmonitorDown.Value),
            alertOnHaChange = Field(stored.AlertOnHaChange is null, effective.AlertOnHaChange, effective.AlertOnHaChange.Value)
        };
    }

    public static string Phrase<T>(ResolvedValue<T> field)
        => field.Scope == PolicyScope.Device ? "on this device" : "from " + field.Source;

    private static object Field<T>(bool inherited, ResolvedValue<T> resolved, object? value) => new
    {
        value,
        inherited,
        source = resolved.Source,
        scope = resolved.Scope.ToString().ToLowerInvariant(),
        phrase = Phrase(resolved)
    };

    private static object SecretField(string? stored, ResolvedValue<string> resolved) => new
    {
        state = PolicyResolver.SecretState(stored),
        inherited = stored is null,
        source = resolved.Source,
        scope = resolved.Scope.ToString().ToLowerInvariant(),
        phrase = Phrase(resolved)
    };

    private static string? Secret(bool use, string? posted, string? current)
    {
        if (!use)
        {
            return null;
        }

        if (string.IsNullOrEmpty(posted))
        {
            return current ?? "";
        }

        return posted;
    }

    private static bool TryVersion(string? text, out SnmpVersion version)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            version = SnmpVersion.V2C;
            return false;
        }

        if (Enum.TryParse<SnmpVersion>(text.Trim(), true, out version) && version is SnmpVersion.V1 or SnmpVersion.V2C or SnmpVersion.V3)
        {
            return true;
        }

        return CsvDevices.TryParseVersion(text, out version) && !string.IsNullOrWhiteSpace(text);
    }

    private static (bool Name, bool Descr, bool Alias) Fields(string? text)
    {
        if (!InterfaceMonitor.TryParseFields(text, out var name, out var descr, out var alias))
        {
            return (true, true, true);
        }

        return (name, descr, alias);
    }

    private static string NormalizeProtocol(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static bool IsAuth(string value)
        => value.Equals("None", StringComparison.OrdinalIgnoreCase)
            || value.Equals("MD5", StringComparison.OrdinalIgnoreCase)
            || value.Equals("SHA1", StringComparison.OrdinalIgnoreCase)
            || value.Equals("SHA", StringComparison.OrdinalIgnoreCase)
            || value.Equals("SHA256", StringComparison.OrdinalIgnoreCase)
            || value.Equals("SHA384", StringComparison.OrdinalIgnoreCase)
            || value.Equals("SHA512", StringComparison.OrdinalIgnoreCase);

    private static bool IsPriv(string value)
        => value.Equals("None", StringComparison.OrdinalIgnoreCase)
            || value.Equals("DES", StringComparison.OrdinalIgnoreCase)
            || value.Equals("AES", StringComparison.OrdinalIgnoreCase)
            || value.Equals("AES128", StringComparison.OrdinalIgnoreCase)
            || value.Equals("AES192", StringComparison.OrdinalIgnoreCase)
            || value.Equals("AES256", StringComparison.OrdinalIgnoreCase);

    private static string DisplayName(string key, IEnumerable<string?> raw)
    {
        if (key.Length == 0)
        {
            return LocationGroups.UnassignedName;
        }

        return raw
            .Select(value => (value ?? "").Trim())
            .Where(value => value.Length > 0 && LocationGroups.KeyFor(value) == key)
            .GroupBy(value => value, StringComparer.Ordinal)
            .Select(group => (Name: group.Key, Count: group.Count()))
            .OrderByDescending(item => item.Count)
            .ThenBy(item => item.Name, StringComparer.Ordinal)
            .Select(item => item.Name)
            .FirstOrDefault() ?? key;
    }
}
