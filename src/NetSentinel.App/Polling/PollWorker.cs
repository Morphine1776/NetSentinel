using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Services;
using NetSentinel.Snmp;

namespace NetSentinel.Polling;

public sealed class PollWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly DevicePoller _poller;
    private readonly IOptions<SnmpOptions> _options;
    private readonly ILogger<PollWorker> _logger;

    public PollWorker(
        IServiceScopeFactory scopes,
        DevicePoller poller,
        IOptions<SnmpOptions> options,
        ILogger<PollWorker> logger)
    {
        _scopes = scopes;
        _poller = poller;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        var gate = new SemaphoreSlim(Math.Max(1, _options.Value.MaxConcurrentPolls));
        while (!stoppingToken.IsCancellationRequested)
        {
            List<int> due = new();
            try
            {
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var now = DateTime.UtcNow;
                due = await db.Devices.AsNoTracking()
                    .Where(device => device.Enabled && (device.NextPollAt == null || device.NextPollAt <= now))
                    .Select(device => device.Id)
                    .ToListAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Could not list devices due for polling");
            }

            var polls = due.Select(async id =>
            {
                await gate.WaitAsync(stoppingToken);
                try
                {
                    await PollDeviceAsync(id, stoppingToken);
                }
                finally
                {
                    gate.Release();
                }
            }).ToList();

            try
            {
                await Task.WhenAll(polls);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }

    private async Task PollDeviceAsync(int id, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var device = await db.Devices.Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
            if (device is null || !device.Enabled)
            {
                return;
            }

            var options = _options.Value;
            var target = new DevicePollTarget(
                device.Host,
                device.Port,
                device.Version,
                device.Community,
                device.V3User,
                device.V3Context,
                device.V3AuthProtocol,
                device.V3AuthPassword,
                device.V3PrivProtocol,
                device.V3PrivPassword,
                device.CustomOids.Select(oid => new CustomOidTarget(oid.Id, oid.Name, oid.Oid)).ToList(),
                options.TimeoutMs,
                options.Retries);

            PollResult result;
            try
            {
                result = await _poller.PollAsync(target, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result = new PollResult { SnmpOk = false, Error = ex.Message, SampledAt = DateTime.UtcNow };
            }

            var states = await db.InterfaceStates.Where(state => state.DeviceId == id).ToListAsync(cancellationToken);
            var settings = await db.Settings.OrderBy(item => item.Id).FirstAsync(cancellationToken);
            var previous = device.LastPollAt is null
                ? null
                : new PollSnapshot(
                    device.LastSnmpOk == true,
                    device.LastPingOk,
                    device.LastResponseMs,
                    device.LastSysUpTimeTicks,
                    states.Where(state => state.Present).Select(ToSnapshot).ToList(),
                    Array.Empty<CustomSnapshot>());

            var uptimeReset = CounterMath.IsUptimeReset(device.LastSysUpTimeTicks, result.SysUpTimeTicks);
            var currentInterfaces = new List<InterfaceSnapshot>();
            var monitorRules = InterfaceMonitorService.RulesFor(device);
            if (result.SnmpOk)
            {
                var seen = new HashSet<int>();
                foreach (var reading in result.Interfaces)
                {
                    seen.Add(reading.IfIndex);
                    var state = states.FirstOrDefault(item => item.IfIndex == reading.IfIndex);
                    double? inBps = null;
                    double? outBps = null;
                    double? inUtil = null;
                    double? outUtil = null;
                    if (state is { Present: true } && state.CounterBits == reading.CounterBits)
                    {
                        var elapsed = (result.SampledAt - state.UpdatedAt).TotalSeconds;
                        inBps = CounterMath.BitsPerSecond(CounterStorage.Unpack(state.InOctets), reading.InOctets, reading.CounterBits, elapsed, uptimeReset);
                        outBps = CounterMath.BitsPerSecond(CounterStorage.Unpack(state.OutOctets), reading.OutOctets, reading.CounterBits, elapsed, uptimeReset);
                        inUtil = CounterMath.UtilizationPercent(inBps, reading.SpeedBps);
                        outUtil = CounterMath.UtilizationPercent(outBps, reading.SpeedBps);
                    }

                    if (state is null)
                    {
                        state = new InterfaceState { DeviceId = id, IfIndex = reading.IfIndex };
                        db.InterfaceStates.Add(state);
                        states.Add(state);
                    }

                    state.IfDescr = reading.IfDescr;
                    state.IfName = reading.IfName;
                    state.IfAlias = reading.IfAlias;
                    state.AdminStatus = reading.AdminStatus;
                    state.OperStatus = reading.OperStatus;
                    state.SpeedBps = CounterStorage.Pack(reading.SpeedBps);
                    state.InOctets = CounterStorage.Pack(reading.InOctets);
                    state.OutOctets = CounterStorage.Pack(reading.OutOctets);
                    state.CounterBits = reading.CounterBits;
                    state.InBps = inBps;
                    state.OutBps = outBps;
                    state.InUtil = inUtil;
                    state.OutUtil = outUtil;
                    state.Present = true;
                    state.UpdatedAt = result.SampledAt;
                    var monitored = InterfaceMonitor.Evaluate(
                        new InterfaceIdentity(reading.IfName, reading.IfDescr, reading.IfAlias, reading.AdminStatus),
                        monitorRules,
                        state.MonitorOverride);
                    state.Monitored = monitored;

                    if (monitored)
                    {
                        db.InterfaceSamples.Add(new InterfaceSample
                        {
                            DeviceId = id,
                            IfIndex = reading.IfIndex,
                            Timestamp = result.SampledAt,
                            OperStatus = reading.OperStatus,
                            InBps = inBps,
                            OutBps = outBps,
                            InUtil = inUtil,
                            OutUtil = outUtil
                        });
                    }

                    currentInterfaces.Add(new InterfaceSnapshot(
                        reading.IfIndex,
                        reading.IfDescr,
                        reading.IfName,
                        reading.AdminStatus,
                        reading.OperStatus,
                        inBps,
                        outBps,
                        inUtil,
                        outUtil,
                        monitored));
                }

                foreach (var state in states.Where(item => !seen.Contains(item.IfIndex)))
                {
                    state.Present = false;
                }

                await ReplaceDiscoveredLinksAsync(db, device.Id, result.Neighbors, states, cancellationToken);
            }

            var customs = new List<CustomSnapshot>();
            if (result.SnmpOk)
            {
                foreach (var reading in result.CustomOids)
                {
                    var entity = device.CustomOids.FirstOrDefault(item => item.Id == reading.Id);
                    double? rate = null;
                    if (entity is not null
                        && reading.CounterBits is int bits
                        && ulong.TryParse(reading.RawValue, out var currentCounter)
                        && entity.LastRaw is not null
                        && ulong.TryParse(entity.LastRaw, out var previousCounter)
                        && entity.LastAt is DateTime lastAt)
                    {
                        rate = CounterMath.UnitsPerSecond(previousCounter, currentCounter, bits, (result.SampledAt - lastAt).TotalSeconds, uptimeReset);
                    }

                    if (entity is not null)
                    {
                        entity.LastRaw = reading.RawValue;
                        entity.LastNumeric = reading.NumericValue;
                        entity.LastRate = rate;
                        entity.LastAt = result.SampledAt;
                    }

                    if (reading.Id > 0)
                    {
                        db.CustomOidSamples.Add(new CustomOidSample
                        {
                            DeviceId = id,
                            CustomOidId = reading.Id,
                            Timestamp = result.SampledAt,
                            RawValue = reading.RawValue,
                            NumericValue = reading.NumericValue,
                            RatePerSecond = rate,
                            CounterBits = reading.CounterBits
                        });
                    }

                    customs.Add(new CustomSnapshot(reading.Id, reading.Name, reading.NumericValue, rate));
                }
            }

            db.DeviceSamples.Add(new DeviceSample
            {
                DeviceId = id,
                Timestamp = result.SampledAt,
                PingOk = result.PingOk == true,
                PingKnown = result.PingOk is not null,
                SnmpOk = result.SnmpOk,
                ResponseMs = result.ResponseTimeMs,
                SysUpTimeTicks = result.SysUpTimeTicks
            });

            if (result.SnmpOk)
            {
                device.ConsecutiveFailures = 0;
                device.LastSysDescr = result.SysDescr;
                device.LastSysName = result.SysName;
                device.LastSysUpTimeTicks = result.SysUpTimeTicks;
                device.LastError = null;
            }
            else
            {
                device.ConsecutiveFailures++;
                device.LastError = result.Error;
            }

            device.LastPingOk = result.PingOk;
            device.LastSnmpOk = result.SnmpOk;
            device.LastResponseMs = result.ResponseTimeMs;
            device.LastPollAt = result.SampledAt;
            device.NextPollAt = DateTime.UtcNow.AddSeconds(Math.Max(5, device.PollIntervalSeconds));

            var rules = await db.Rules.AsNoTracking()
                .Where(rule => rule.Enabled && (rule.DeviceId == null || rule.DeviceId == device.Id))
                .ToListAsync(cancellationToken);
            var openKeys = await db.Alerts.AsNoTracking()
                .Where(alert => alert.DeviceId == device.Id && alert.State != AlertState.Resolved)
                .Select(alert => alert.DedupKey)
                .ToListAsync(cancellationToken);

            var transitions = AlertEvaluator.Evaluate(
                $"device:{device.Id}",
                device.Name,
                previous,
                new PollSnapshot(result.SnmpOk, result.PingOk, result.ResponseTimeMs, result.SysUpTimeTicks, currentInterfaces, customs),
                device.ConsecutiveFailures,
                Math.Max(1, settings.FailureThreshold),
                rules.Select(rule => new AlertRuleModel(rule.Id, rule.Name, rule.Metric, rule.InterfaceFilter, rule.Operator, rule.Threshold, rule.Severity)).ToList(),
                openKeys.ToHashSet(StringComparer.Ordinal));

            var now = DateTime.UtcNow;
            foreach (var transition in transitions)
            {
                if (transition.Type == AlertTransitionType.Open)
                {
                    db.Alerts.Add(new AlertEvent
                    {
                        DeviceId = device.Id,
                        DedupKey = transition.DedupKey,
                        Kind = transition.Kind,
                        Severity = transition.Severity,
                        Message = transition.Message,
                        State = AlertState.Open,
                        IfIndex = transition.IfIndex,
                        RuleId = transition.RuleId,
                        CreatedAt = now
                    });
                    continue;
                }

                var matches = await db.Alerts
                    .Where(alert => alert.DedupKey == transition.DedupKey && alert.State != AlertState.Resolved)
                    .ToListAsync(cancellationToken);
                foreach (var alert in matches)
                {
                    alert.State = AlertState.Resolved;
                    alert.ResolvedAt = now;
                }
            }

            await SaveAsync(db, cancellationToken);
            if (transitions.Count > 0)
            {
                var email = scope.ServiceProvider.GetRequiredService<EmailNotifier>();
                await email.NotifyAsync(device.Name, transitions, cancellationToken);
            }

            _logger.LogInformation(
                "Polled {Name} ({Host}) snmp={Snmp} ping={Ping} interfaces={Interfaces}",
                device.Name,
                device.Host,
                result.SnmpOk,
                result.PingOk,
                result.Interfaces.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Poll failed for device {Id}", id);
        }
    }

    private static async Task ReplaceDiscoveredLinksAsync(
        AppDbContext db,
        int deviceId,
        IReadOnlyList<NeighborObservation> neighbors,
        IReadOnlyList<InterfaceState> states,
        CancellationToken cancellationToken)
    {
        var known = await db.Devices.AsNoTracking()
            .Select(item => new KnownDevice(item.Id, item.Name, item.Host, item.LastSysName))
            .ToListAsync(cancellationToken);
        var interfaces = states.Where(state => state.Present).Select(state => new KnownInterface(
            state.IfIndex,
            state.IfDescr,
            state.IfName,
            state.IfAlias,
            state.InUtil,
            state.OutUtil)).ToList();
        var matched = NeighborMatcher.Match(deviceId, neighbors, known, interfaces);
        var stale = await db.Links
            .Where(link => link.SourceDeviceId == deviceId && (link.Kind == "lldp" || link.Kind == "cdp"))
            .ToListAsync(cancellationToken);
        db.Links.RemoveRange(stale);
        var now = DateTime.UtcNow;
        foreach (var link in matched)
        {
            db.Links.Add(new DeviceLink
            {
                SourceDeviceId = deviceId,
                TargetDeviceId = link.RemoteDeviceId,
                Kind = link.Protocol,
                LocalIfIndex = link.LocalIfIndex,
                LocalPort = link.LocalPort,
                RemotePort = link.RemotePort,
                Utilization = link.Utilization,
                UpdatedAt = now
            });
        }
    }

    private static InterfaceSnapshot ToSnapshot(InterfaceState state) => new(
        state.IfIndex,
        state.IfDescr,
        state.IfName,
        state.AdminStatus,
        state.OperStatus,
        state.InBps,
        state.OutBps,
        state.InUtil,
        state.OutUtil,
        state.Monitored);

    private static async Task SaveAsync(AppDbContext db, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                return;
            }
            catch (DbUpdateException ex) when (attempt < 4 && ex.InnerException?.Message.Contains("locked", StringComparison.OrdinalIgnoreCase) == true)
            {
                await Task.Delay(80 * (attempt + 1), cancellationToken);
            }
        }
    }
}
