using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Services;
using NetSentinel.Snmp;
using Lextm.SharpSnmpLib.Security;

namespace NetSentinel.Polling;

public sealed class TrapWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<TrapWorker> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _sync = new();
    private CancellationToken _hostToken = CancellationToken.None;
    private CancellationTokenSource? _session;
    private UdpClient? _client;
    private Task? _loop;

    public TrapWorker(IServiceScopeFactory scopes, ILogger<TrapWorker> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _hostToken = stoppingToken;
        try
        {
            await ReconfigureAsync(stoppingToken);
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await StopListenerAsync();
        await base.StopAsync(cancellationToken);
    }

    public async Task ReconfigureAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var settings = await db.Settings.AsNoTracking().OrderBy(item => item.Id).FirstOrDefaultAsync(cancellationToken);
            var enabled = settings?.TrapEnabled ?? false;
            var port = settings?.TrapPort ?? 1162;
            await StopListenerAsync();
            if (!enabled)
            {
                _logger.LogInformation("SNMP trap listener is disabled");
                return;
            }

            if (port is < 1 or > 65535)
            {
                _logger.LogError("Trap port {Port} is invalid", port);
                return;
            }

            var client = new UdpClient(AddressFamily.InterNetwork);
            try
            {
                client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
            }
            catch (Exception ex)
            {
                client.Dispose();
                _logger.LogError(ex, "Could not bind the trap listener to UDP {Port}", port);
                return;
            }

            var session = CancellationTokenSource.CreateLinkedTokenSource(_hostToken);
            var loop = Task.Run(() => ReceiveLoop(client, session.Token), CancellationToken.None);
            lock (_sync)
            {
                _client = client;
                _session = session;
                _loop = loop;
            }

            _logger.LogInformation("Listening for SNMP traps on UDP {Port}", port);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task StopListenerAsync()
    {
        CancellationTokenSource? session;
        UdpClient? client;
        Task? loop;
        lock (_sync)
        {
            session = _session;
            client = _client;
            loop = _loop;
            _session = null;
            _client = null;
            _loop = null;
        }

        session?.Cancel();
        client?.Dispose();
        if (loop is not null)
        {
            try
            {
                await loop.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (Exception)
            {
            }
        }

        session?.Dispose();
    }

    private async Task ReceiveLoop(UdpClient client, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await client.ReceiveAsync(cancellationToken);
            }
            catch (Exception) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }

            try
            {
                await StoreAsync(client, result, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to store an SNMP trap from {Source}", result.RemoteEndPoint);
            }
        }
    }

    private async Task StoreAsync(UdpClient client, UdpReceiveResult result, CancellationToken cancellationToken)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var registry = new UserRegistry();
        var devices = await db.Devices.AsNoTracking()
            .Where(device => device.Version == Core.SnmpVersion.V3 && device.V3User != "")
            .ToListAsync(cancellationToken);
        foreach (var device in devices)
        {
            try
            {
                registry.Add(new Lextm.SharpSnmpLib.OctetString(device.V3User), SnmpPrivacy.Create(device.V3AuthProtocol, device.V3AuthPassword, device.V3PrivProtocol, device.V3PrivPassword));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Skipped v3 trap credentials for {Device}", device.Name);
            }
        }

        IReadOnlyList<ParsedTrap> traps;
        try
        {
            traps = SnmpTrapParser.Parse(result.Buffer, registry);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Ignored an undecodable SNMP datagram from {Source}", result.RemoteEndPoint);
            return;
        }

        if (traps.Count == 0)
        {
            return;
        }

        try
        {
            var messages = Lextm.SharpSnmpLib.Messaging.MessageFactory.ParseMessages(result.Buffer, 0, result.Buffer.Length, registry);
            foreach (var message in messages)
            {
                var response = SnmpTrapParser.InformResponse(message);
                if (response is not null)
                {
                    await client.SendAsync(response, result.RemoteEndPoint, cancellationToken);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not acknowledge an SNMP inform");
        }

        var now = DateTime.UtcNow;
        foreach (var trap in traps)
        {
            var text = trap.Varbinds.Length > 8000 ? trap.Varbinds[..8000] : trap.Varbinds;
            db.Traps.Add(new TrapEvent
            {
                ReceivedAt = now,
                Source = result.RemoteEndPoint.ToString(),
                Version = trap.Version,
                SecurityName = trap.SecurityName,
                TrapOid = trap.TrapOid,
                Summary = trap.Summary,
                Varbinds = text
            });
        }

        var transitions = await InterfaceTrapAlerts.ApplyAsync(db, result.RemoteEndPoint.Address, traps, _logger, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if (transitions.Count > 0)
        {
            var email = scope.ServiceProvider.GetRequiredService<EmailNotifier>();
            foreach (var group in transitions.GroupBy(item => item.DeviceName))
            {
                await email.NotifyAsync(group.Key, group.Select(item => item.Transition).ToList(), cancellationToken);
            }
        }

        _logger.LogInformation("Stored {Count} SNMP trap(s) from {Source}", traps.Count, result.RemoteEndPoint);
    }
}

internal static class InterfaceTrapAlerts
{
    public static async Task<List<(string DeviceName, AlertTransition Transition)>> ApplyAsync(
        AppDbContext db,
        System.Net.IPAddress source,
        IReadOnlyList<ParsedTrap> traps,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var interesting = traps.Where(trap => trap.LinkEvent is "down" or "up" && trap.IfIndex is int).ToList();
        var transitions = new List<(string DeviceName, AlertTransition Transition)>();
        if (interesting.Count == 0)
        {
            return transitions;
        }

        var devices = await db.Devices.AsNoTracking().ToListAsync(cancellationToken);
        var matched = devices.Where(device => HostMatches(device.Host, source)).ToList();
        if (matched.Count == 0)
        {
            return transitions;
        }

        var ids = matched.Select(device => device.Id).ToList();
        var indexes = interesting.Select(trap => trap.IfIndex!.Value).ToHashSet();
        var states = await db.InterfaceStates
            .Where(state => ids.Contains(state.DeviceId) && indexes.Contains(state.IfIndex))
            .ToListAsync(cancellationToken);
        var names = devices.ToDictionary(device => device.Id, device => device.Name);
        var now = DateTime.UtcNow;
        foreach (var trap in interesting)
        {
            foreach (var state in states.Where(state => state.IfIndex == trap.IfIndex))
            {
                var effect = InterfaceTrapPolicy.Decide(trap.LinkEvent, state.Monitored);
                var deviceName = names.GetValueOrDefault(state.DeviceId) ?? $"device {state.DeviceId}";
                if (effect == InterfaceTrapEffect.Suppress)
                {
                    logger.LogInformation(
                        "Ignored {Event} trap for unmonitored ifIndex {IfIndex} on {Device}",
                        trap.LinkEvent,
                        state.IfIndex,
                        deviceName);
                    continue;
                }

                if (effect == InterfaceTrapEffect.None)
                {
                    continue;
                }

                var scope = $"device:{state.DeviceId}";
                var key = $"{scope}:if:{state.IfIndex}:down";
                var label = InterfaceLabel(state);
                if (effect == InterfaceTrapEffect.OpenDown)
                {
                    var open = await db.Alerts.AnyAsync(alert => alert.DedupKey == key && alert.State != AlertState.Resolved, cancellationToken);
                    if (open)
                    {
                        continue;
                    }

                    var transition = new AlertTransition(
                        AlertTransitionType.Open,
                        key,
                        AlertKind.InterfaceDown,
                        AlertSeverity.Warning,
                        $"Interface {label} on {deviceName} is down (linkDown trap).",
                        state.IfIndex,
                        null);
                    db.Alerts.Add(Create(state.DeviceId, transition, now));
                    transitions.Add((deviceName, transition));
                    continue;
                }

                var alerts = await db.Alerts
                    .Where(alert => alert.DedupKey == key && alert.State != AlertState.Resolved)
                    .ToListAsync(cancellationToken);
                if (alerts.Count == 0)
                {
                    continue;
                }

                foreach (var alert in alerts)
                {
                    alert.State = AlertState.Resolved;
                    alert.ResolvedAt = now;
                }

                var resolve = new AlertTransition(
                    AlertTransitionType.Resolve,
                    key,
                    AlertKind.InterfaceDown,
                    AlertSeverity.Warning,
                    $"Interface {label} on {deviceName} is up (linkUp trap).",
                    state.IfIndex,
                    null);
                transitions.Add((deviceName, resolve));
                var up = new AlertTransition(
                    AlertTransitionType.Open,
                    $"{scope}:if:{state.IfIndex}:up:trap:{now.Ticks}",
                    AlertKind.InterfaceUp,
                    AlertSeverity.Info,
                    $"Interface {label} on {deviceName} is up (linkUp trap).",
                    state.IfIndex,
                    null);
                db.Alerts.Add(Create(state.DeviceId, up, now));
                transitions.Add((deviceName, up));
            }
        }

        return transitions;
    }

    private static AlertEvent Create(int deviceId, AlertTransition transition, DateTime now) => new()
    {
        DeviceId = deviceId,
        DedupKey = transition.DedupKey,
        Kind = transition.Kind,
        Severity = transition.Severity,
        Message = transition.Message,
        State = AlertState.Open,
        IfIndex = transition.IfIndex,
        RuleId = transition.RuleId,
        CreatedAt = now
    };

    private static string InterfaceLabel(InterfaceState state)
    {
        if (!string.IsNullOrWhiteSpace(state.IfName))
        {
            return state.IfName;
        }

        if (!string.IsNullOrWhiteSpace(state.IfDescr))
        {
            return state.IfDescr;
        }

        return $"if{state.IfIndex}";
    }

    private static bool HostMatches(string host, System.Net.IPAddress address)
        => System.Net.IPAddress.TryParse(host, out var parsed) && parsed.Equals(address);
}
