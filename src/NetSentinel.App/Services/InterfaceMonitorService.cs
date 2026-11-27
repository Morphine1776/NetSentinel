using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class InterfacePolicyInput
{
    public string? IncludePattern { get; set; }
    public string? ExcludePattern { get; set; }
    public string? Syntax { get; set; }
    public bool MatchName { get; set; } = true;
    public bool MatchDescr { get; set; } = true;
    public bool MatchAlias { get; set; } = true;
    public bool ExcludeAdminDown { get; set; }
    public bool RequireAlias { get; set; }
}

public sealed class InterfaceMonitorUpdate
{
    public bool Monitored { get; set; }
    public bool ClearOverride { get; set; }
}

public sealed class InterfaceBulkRequest
{
    public string? Action { get; set; }
    public List<int>? IfIndexes { get; set; }
}

public sealed class InterfaceMonitorService
{
    private readonly AppDbContext _db;

    public InterfaceMonitorService(AppDbContext db)
    {
        _db = db;
    }

    public static InterfaceMonitorRules RulesFor(Device device, PolicyCatalog catalog)
        => catalog.Resolve(device).InterfaceRules();

    public static InterfacePolicyInput ReadInput(ResolvedPolicy policy)
    {
        var rules = policy.InterfaceRules();
        return new InterfacePolicyInput
        {
            IncludePattern = rules.IncludePattern,
            ExcludePattern = rules.ExcludePattern,
            Syntax = InterfaceMonitor.FormatSyntax(rules.Syntax),
            MatchName = rules.MatchName,
            MatchDescr = rules.MatchDescr,
            MatchAlias = rules.MatchAlias,
            ExcludeAdminDown = rules.ExcludeAdminDown,
            RequireAlias = rules.RequireAlias
        };
    }

    public static object PolicyJson(ResolvedPolicy policy)
    {
        var input = ReadInput(policy);
        return new
        {
            includePattern = input.IncludePattern,
            excludePattern = input.ExcludePattern,
            syntax = input.Syntax,
            matchName = input.MatchName,
            matchDescr = input.MatchDescr,
            matchAlias = input.MatchAlias,
            excludeAdminDown = input.ExcludeAdminDown,
            requireAlias = input.RequireAlias
        };
    }

    public async Task<string?> SavePolicyAsync(int deviceId, InterfacePolicyInput input, CancellationToken cancellationToken = default)
    {
        var rules = Bind(input, out var error);
        if (error is not null)
        {
            return error;
        }

        var device = await _db.Devices.FirstOrDefaultAsync(item => item.Id == deviceId, cancellationToken);
        if (device is null)
        {
            return "That device no longer exists.";
        }

        Write(device, rules!);
        device.UpdatedAt = DateTime.UtcNow;
        var states = await _db.InterfaceStates.Where(state => state.DeviceId == deviceId).ToListAsync(cancellationToken);
        await ApplyAsync(device, states, cancellationToken);
        await ResolveQuietAsync(deviceId, states, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        return null;
    }

    public async Task ReapplyAsync(int deviceId, CancellationToken cancellationToken = default)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(item => item.Id == deviceId, cancellationToken);
        if (device is null)
        {
            return;
        }

        var states = await _db.InterfaceStates.Where(state => state.DeviceId == deviceId).ToListAsync(cancellationToken);
        await ApplyAsync(device, states, cancellationToken);
        await ResolveQuietAsync(deviceId, states, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<(bool Ok, string? Error)> SetAsync(int deviceId, int ifIndex, InterfaceMonitorUpdate update, CancellationToken cancellationToken = default)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(item => item.Id == deviceId, cancellationToken);
        var state = await _db.InterfaceStates.FirstOrDefaultAsync(item => item.DeviceId == deviceId && item.IfIndex == ifIndex, cancellationToken);
        if (device is null || state is null)
        {
            return (false, "That interface was not found. It appears after a poll discovers it.");
        }

        if (update.ClearOverride)
        {
            state.MonitorOverride = null;
        }
        else
        {
            state.MonitorOverride = update.Monitored;
        }

        await ApplyAsync(device, new[] { state }, cancellationToken);
        await ResolveQuietAsync(deviceId, new[] { state }, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        return (true, null);
    }

    public async Task<string?> BulkAsync(int deviceId, string? action, IReadOnlyCollection<int>? selected, CancellationToken cancellationToken = default)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(item => item.Id == deviceId, cancellationToken);
        if (device is null)
        {
            return "That device no longer exists.";
        }

        var states = await _db.InterfaceStates.Where(state => state.DeviceId == deviceId).ToListAsync(cancellationToken);
        var picked = selected?.ToHashSet() ?? new HashSet<int>();
        switch ((action ?? "").Trim().ToLowerInvariant())
        {
            case "only-selected":
            case "onlyselected":
                if (picked.Count == 0)
                {
                    return "Select at least one interface to keep monitoring.";
                }

                if (states.All(state => !picked.Contains(state.IfIndex)))
                {
                    return "None of the selected interfaces belong to this device.";
                }

                foreach (var state in states)
                {
                    state.MonitorOverride = picked.Contains(state.IfIndex);
                }

                break;
            case "unmonitor-down":
            case "unmonitordown":
                foreach (var state in states.Where(IsDown))
                {
                    state.MonitorOverride = false;
                }

                break;
            case "clear-overrides":
            case "clearoverrides":
                foreach (var state in states)
                {
                    state.MonitorOverride = null;
                }

                break;
            default:
                return "Action must be only-selected, unmonitor-down, or clear-overrides.";
        }

        await ApplyAsync(device, states, cancellationToken);
        await ResolveQuietAsync(deviceId, states, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        return null;
    }

    public async Task ApplyAsync(Device device, IEnumerable<InterfaceState> states, CancellationToken cancellationToken = default)
    {
        var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
        Apply(RulesFor(device, catalog), states);
    }

    public static void Apply(InterfaceMonitorRules rules, IEnumerable<InterfaceState> states)
    {
        foreach (var state in states)
        {
            state.Monitored = InterfaceMonitor.Evaluate(Identity(state), rules, state.MonitorOverride);
        }
    }

    public static InterfaceIdentity Identity(InterfaceState state)
        => new(state.IfName ?? "", state.IfDescr ?? "", state.IfAlias ?? "", state.AdminStatus, state.OperStatus);

    public static bool IsDown(InterfaceState state)
        => state.AdminStatus == InterfaceMonitor.AdminDown || state.OperStatus is 2 or 7;

    private static InterfaceMonitorRules? Bind(InterfacePolicyInput input, out string? error)
    {
        if (!InterfaceMonitor.TrySyntax(input.Syntax, out var syntax))
        {
            error = "Pattern syntax must be glob or regex.";
            return null;
        }

        var rules = new InterfaceMonitorRules(
            (input.IncludePattern ?? "").Trim(),
            (input.ExcludePattern ?? "").Trim(),
            syntax,
            input.MatchName,
            input.MatchDescr,
            input.MatchAlias,
            input.ExcludeAdminDown,
            input.RequireAlias);
        error = InterfaceMonitor.Validate(rules);
        return error is null ? rules : null;
    }

    private static void Write(Device device, InterfaceMonitorRules rules)
    {
        device.IfIncludePattern = rules.IncludePattern;
        device.IfExcludePattern = rules.ExcludePattern;
        device.IfPatternSyntax = InterfaceMonitor.FormatSyntax(rules.Syntax);
        device.IfMatchFields = InterfaceMonitor.FormatFields(rules.MatchName, rules.MatchDescr, rules.MatchAlias);
        device.IfExcludeAdminDown = rules.ExcludeAdminDown;
        device.IfRequireAlias = rules.RequireAlias;
    }

    private async Task ResolveQuietAsync(int deviceId, IEnumerable<InterfaceState> states, CancellationToken cancellationToken)
    {
        var quiet = states.Where(state => !state.Monitored).Select(state => state.IfIndex).Distinct().ToList();
        if (quiet.Count == 0)
        {
            return;
        }

        var alerts = await _db.Alerts
            .Where(alert => alert.DeviceId == deviceId
                && alert.State != AlertState.Resolved
                && alert.IfIndex != null
                && quiet.Contains(alert.IfIndex.Value)
                && (alert.Kind == AlertKind.InterfaceDown || alert.Kind == AlertKind.Threshold))
            .ToListAsync(cancellationToken);
        var now = DateTime.UtcNow;
        foreach (var alert in alerts)
        {
            alert.State = AlertState.Resolved;
            alert.ResolvedAt = now;
        }
    }
}
