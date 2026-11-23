using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Polling;

public sealed class RetentionWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly IConfiguration _configuration;
    private readonly ILogger<RetentionWorker> _logger;

    public RetentionWorker(IServiceScopeFactory scopes, IConfiguration configuration, ILogger<RetentionWorker> logger)
    {
        _scopes = scopes;
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var minutes = Math.Clamp(_configuration.GetValue("Retention:CleanupIntervalMinutes", 60), 5, 24 * 60);
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Retention cleanup failed");
            }

            await Task.Delay(TimeSpan.FromMinutes(minutes), stoppingToken);
        }
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var settings = await db.Settings.AsNoTracking().OrderBy(item => item.Id).FirstOrDefaultAsync(cancellationToken);
        var days = Math.Clamp(settings?.RetentionDays ?? 30, 1, 3650);
        var cutoff = DateTime.UtcNow.AddDays(-days);
        var samples = await db.DeviceSamples.Where(item => item.Timestamp < cutoff).ExecuteDeleteAsync(cancellationToken);
        var interfaces = await db.InterfaceSamples.Where(item => item.Timestamp < cutoff).ExecuteDeleteAsync(cancellationToken);
        var customs = await db.CustomOidSamples.Where(item => item.Timestamp < cutoff).ExecuteDeleteAsync(cancellationToken);
        var traps = await db.Traps.Where(item => item.ReceivedAt < cutoff).ExecuteDeleteAsync(cancellationToken);
        var alerts = await db.Alerts
            .Where(item => item.State == AlertState.Resolved && item.ResolvedAt != null && item.ResolvedAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
        _logger.LogInformation(
            "Retention removed {Samples} device samples, {Interfaces} interface samples, {Customs} custom samples, {Traps} traps, {Alerts} resolved alerts older than {Days} days",
            samples, interfaces, customs, traps, alerts, days);
    }
}
