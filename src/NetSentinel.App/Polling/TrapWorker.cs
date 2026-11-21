using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;
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

        await db.SaveChangesAsync(cancellationToken);
        _logger.LogInformation("Stored {Count} SNMP trap(s) from {Source}", traps.Count, result.RemoteEndPoint);
    }
}
