using System.Text;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Polling;
using NetSentinel.Services;

namespace NetSentinel.Web;

public static class ApiEndpoints
{
    public static void MapNetSentinelApi(this WebApplication app)
    {
        var api = app.MapGroup("/api").RequireAuthorization();

        api.MapGet("/devices", async (AppDbContext db) =>
        {
            var devices = await db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync();
            return Results.Json(devices.Select(device => Summary(device)));
        });

        api.MapGet("/devices/board", async (AppDbContext db, CancellationToken cancellationToken) =>
            Results.Json(await DeviceBoardBuilder.LoadAsync(db, cancellationToken)));

        api.MapGet("/devices/{id:int}/effective-settings", async (int id, AppDbContext db, CancellationToken cancellationToken) =>
        {
            var device = await db.Devices.AsNoTracking().FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
            if (device is null)
            {
                return Results.NotFound();
            }

            var catalog = await PolicyStore.LoadAsync(db, cancellationToken);
            var resolved = catalog.Resolve(device);
            return Results.Json(new
            {
                device.Id,
                location = catalog.LocationName(device),
                ha = HaJson(device),
                settings = PolicyStore.LayerJson(PolicyStore.FromDevice(device), resolved)
            });
        });

        api.MapGet("/policies/global", async (AppDbContext db, CancellationToken cancellationToken) =>
        {
            var catalog = await PolicyStore.LoadAsync(db, cancellationToken);
            var stored = catalog.Global;
            var resolved = PolicyResolver.Resolve(stored, null, null, "Global");
            return Results.Json(PolicyStore.LayerJson(stored, resolved));
        });

        api.MapPut("/policies/global", async (PolicyForm form, AppDbContext db, CancellationToken cancellationToken) =>
        {
            var row = await db.Policies.FirstOrDefaultAsync(policy => policy.Scope == "global", cancellationToken);
            if (row is null)
            {
                return Results.NotFound();
            }

            var written = PolicyStore.ApplyForm(PolicyStore.FromPolicy(row), form, inheritAllowed: false);
            var resolved = PolicyResolver.Resolve(written, null, null, "Global");
            var errors = PolicyStore.Validate(resolved, written, requireConcrete: true);
            if (errors.Count > 0)
            {
                return Results.BadRequest(new { errors });
            }

            PolicyStore.WritePolicy(row, written);
            await db.SaveChangesAsync(cancellationToken);
            return Results.Json(PolicyStore.LayerJson(written, resolved));
        });

        api.MapGet("/policies/locations", async (AppDbContext db, CancellationToken cancellationToken) =>
        {
            await PolicyStore.EnsureLocationsAsync(db, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            var catalog = await PolicyStore.LoadAsync(db, cancellationToken);
            return Results.Json(catalog.Locations.Select(location => new
            {
                key = location.Key,
                name = location.Display,
                settings = PolicyStore.LayerJson(location.Values, PolicyResolver.Resolve(catalog.Global, location.Values, null, location.Display))
            }));
        });

        api.MapGet("/policies/locations/{key}", async (string key, AppDbContext db, CancellationToken cancellationToken) =>
        {
            var catalog = await PolicyStore.LoadAsync(db, cancellationToken);
            if (!catalog.TryLocation(Uri.UnescapeDataString(key), out var display, out var values))
            {
                return Results.NotFound();
            }

            return Results.Json(new
            {
                key = LocationGroups.KeyFor(string.Equals(key, "unassigned", StringComparison.OrdinalIgnoreCase) ? "" : display),
                name = display,
                settings = PolicyStore.LayerJson(values, PolicyResolver.Resolve(catalog.Global, values, null, display))
            });
        });

        api.MapPut("/policies/locations/{key}", async (string key, PolicyForm form, AppDbContext db, CancellationToken cancellationToken) =>
        {
            var normalized = string.Equals(key, "unassigned", StringComparison.OrdinalIgnoreCase) ? "" : LocationGroups.KeyFor(Uri.UnescapeDataString(key));
            var row = await db.Policies.FirstOrDefaultAsync(policy => policy.Scope == "location" && policy.LocationKey == normalized, cancellationToken);
            if (row is null)
            {
                return Results.NotFound();
            }

            var written = PolicyStore.ApplyForm(PolicyStore.FromPolicy(row), form, inheritAllowed: true);
            var resolved = PolicyResolver.Resolve((await PolicyStore.LoadAsync(db, cancellationToken)).Global, written, null, row.DisplayName);
            var errors = PolicyStore.Validate(resolved, written, requireConcrete: false);
            if (errors.Count > 0)
            {
                return Results.BadRequest(new { errors });
            }

            PolicyStore.WritePolicy(row, written);
            await db.SaveChangesAsync(cancellationToken);
            return Results.Json(new
            {
                key = row.LocationKey,
                name = row.DisplayName,
                settings = PolicyStore.LayerJson(written, resolved)
            });
        });

        api.MapGet("/devices/{id:int}", async (int id, bool? monitoredOnly, AppDbContext db) =>
        {
            var device = await db.Devices.AsNoTracking().Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
            if (device is null)
            {
                return Results.NotFound();
            }

            var catalog = await PolicyStore.LoadAsync(db);

            var interfaces = await db.InterfaceStates.AsNoTracking()
                .Where(item => item.DeviceId == id && item.Present)
                .OrderBy(item => item.IfIndex)
                .ToListAsync();
            var unmonitored = interfaces.Count(item => !item.Monitored);
            if (monitoredOnly == true)
            {
                interfaces = interfaces.Where(item => item.Monitored).ToList();
            }

            return Results.Json(new
            {
                device = Summary(device, catalog.Resolve(device)),
                ha = HaJson(device),
                effective = PolicyStore.LayerJson(PolicyStore.FromDevice(device), catalog.Resolve(device)),
                interfacePolicy = InterfaceMonitorService.PolicyJson(catalog.Resolve(device)),
                unmonitored,
                interfaces = interfaces.Select(InterfaceJson),
                customOids = device.CustomOids.Select(oid => new
                {
                    oid.Id,
                    oid.Name,
                    oid.Oid,
                    oid.Unit,
                    oid.LastRaw,
                    oid.LastNumeric,
                    oid.LastRate,
                    oid.LastAt
                })
            });
        });

        api.MapGet("/devices/{id:int}/interface-policy", async (int id, AppDbContext db) =>
        {
            var device = await db.Devices.AsNoTracking().FirstOrDefaultAsync(item => item.Id == id);
            if (device is null)
            {
                return Results.NotFound();
            }

            var catalog = await PolicyStore.LoadAsync(db);
            return Results.Json(InterfaceMonitorService.PolicyJson(catalog.Resolve(device)));
        });

        api.MapPut("/devices/{id:int}/interface-policy", async (int id, InterfacePolicyInput input, InterfaceMonitorService monitor) =>
        {
            var error = await monitor.SavePolicyAsync(id, input);
            if (error is null)
            {
                return Results.Json(input);
            }

            return error == "That device no longer exists."
                ? Results.NotFound()
                : Results.BadRequest(new { errors = new[] { error } });
        });

        api.MapPut("/devices/{id:int}/interfaces/{ifIndex:int}/monitored", async (int id, int ifIndex, InterfaceMonitorUpdate update, InterfaceMonitorService monitor, AppDbContext db) =>
        {
            var (ok, error) = await monitor.SetAsync(id, ifIndex, update);
            if (!ok)
            {
                return Results.NotFound();
            }

            var state = await db.InterfaceStates.AsNoTracking().FirstAsync(item => item.DeviceId == id && item.IfIndex == ifIndex);
            return Results.Json(InterfaceJson(state));
        });

        api.MapPost("/devices/{id:int}/interfaces/monitoring", async (int id, InterfaceBulkRequest body, InterfaceMonitorService monitor) =>
        {
            var error = await monitor.BulkAsync(id, body.Action, body.IfIndexes);
            if (error is null)
            {
                return Results.NoContent();
            }

            return error == "That device no longer exists."
                ? Results.NotFound()
                : Results.BadRequest(new { errors = new[] { error } });
        });

        api.MapPost("/devices", async (DeviceInput input, DeviceAdminService devices) =>
        {
            var saved = await devices.SaveAsync(input);
            return saved.Ok
                ? Results.Json(Summary(saved.Device!), statusCode: StatusCodes.Status201Created)
                : Results.BadRequest(new { errors = saved.Errors });
        });

        api.MapPut("/devices/{id:int}", async (int id, DeviceInput input, DeviceAdminService devices) =>
        {
            input.Id = id;
            var saved = await devices.SaveAsync(input);
            return saved.Ok ? Results.Json(Summary(saved.Device!)) : Results.BadRequest(new { errors = saved.Errors });
        });

        api.MapDelete("/devices/{id:int}", async (int id, DeviceAdminService devices) =>
            await devices.DeleteAsync(id) ? Results.NoContent() : Results.NotFound());

        api.MapGet("/devices/import/template", () =>
            Results.File(Encoding.UTF8.GetBytes(CsvDevices.Template), "text/csv", "netsentinel-devices-template.csv"));

        api.MapGet("/devices/export", async (ImportService imports, CancellationToken cancellationToken) =>
            Results.File(Encoding.UTF8.GetBytes(await imports.ExportAsync(cancellationToken)), "text/csv", "netsentinel-devices.csv"));

        api.MapPost("/devices/import/preview", async (HttpRequest request, ImportService imports, CancellationToken cancellationToken) =>
            Results.Json(await imports.PreviewAsync(await ReadCsvAsync(request, cancellationToken), cancellationToken)));

        api.MapPost("/devices/import", async (ImportCommitRequest body, ImportService imports, CancellationToken cancellationToken) =>
        {
            var result = await imports.CommitAsync(body.Csv, body.DuplicateMode, cancellationToken);
            return result.Error is null ? Results.Json(result) : Results.BadRequest(new { errors = new[] { result.Error } });
        });

        api.MapGet("/map", async (bool? showUnmonitored, MapService map, CancellationToken cancellationToken) =>
            Results.Json(await map.BuildAsync(showUnmonitored == true, cancellationToken)));

        api.MapPost("/map/positions", async (MapPositionBatch batch, MapService map, CancellationToken cancellationToken) =>
        {
            await map.SavePositionsAsync(batch.Positions ?? new List<MapPosition>(), cancellationToken);
            return Results.NoContent();
        });

        api.MapPost("/map/links", async (ManualLinkRequest body, MapService map, CancellationToken cancellationToken) =>
        {
            var (link, error) = await map.AddManualLinkAsync(body.FromId, body.ToId, cancellationToken);
            return error is null ? Results.Json(new { id = link!.Id }) : Results.BadRequest(new { errors = new[] { error } });
        });

        api.MapDelete("/map/links/{id:int}", async (int id, MapService map, CancellationToken cancellationToken) =>
            await map.DeleteManualLinkAsync(id, cancellationToken) ? Results.NoContent() : Results.NotFound());

        api.MapGet("/devices/{id:int}/response", async (int id, int? minutes, AppDbContext db) =>
        {
            var from = DateTime.UtcNow.AddMinutes(-ClampMinutes(minutes));
            var rows = await db.DeviceSamples.AsNoTracking()
                .Where(sample => sample.DeviceId == id && sample.Timestamp >= from)
                .OrderBy(sample => sample.Timestamp)
                .Select(sample => new { sample.Timestamp, sample.ResponseMs })
                .ToListAsync();
            var points = rows.Select(sample => new ChartPoint(sample.Timestamp, null, null, null, null, null, sample.ResponseMs, null, null)).ToList();
            return Results.Json(new { points = Downsample(points) });
        });

        api.MapGet("/devices/{id:int}/interfaces/{ifIndex:int}/history", async (int id, int ifIndex, int? minutes, AppDbContext db) =>
        {
            var from = DateTime.UtcNow.AddMinutes(-ClampMinutes(minutes));
            var rows = await db.InterfaceSamples.AsNoTracking()
                .Where(sample => sample.DeviceId == id && sample.IfIndex == ifIndex && sample.Timestamp >= from)
                .OrderBy(sample => sample.Timestamp)
                .Select(sample => new { sample.Timestamp, sample.InBps, sample.OutBps, sample.InUtil, sample.OutUtil, sample.OperStatus })
                .ToListAsync();
            var points = rows.Select(sample => new ChartPoint(sample.Timestamp, sample.InBps, sample.OutBps, sample.InUtil, sample.OutUtil, sample.OperStatus, null, null, null)).ToList();
            return Results.Json(new { points = Downsample(points) });
        });

        api.MapGet("/devices/{id:int}/custom/{oidId:int}/history", async (int id, int oidId, int? minutes, AppDbContext db) =>
        {
            var from = DateTime.UtcNow.AddMinutes(-ClampMinutes(minutes));
            var rows = await db.CustomOidSamples.AsNoTracking()
                .Where(sample => sample.DeviceId == id && sample.CustomOidId == oidId && sample.Timestamp >= from)
                .OrderBy(sample => sample.Timestamp)
                .Select(sample => new { sample.Timestamp, sample.NumericValue, sample.RatePerSecond })
                .ToListAsync();
            var points = rows.Select(sample => new ChartPoint(sample.Timestamp, null, null, null, null, null, null, sample.NumericValue, sample.RatePerSecond)).ToList();
            return Results.Json(new { points = Downsample(points) });
        });

        api.MapGet("/alerts", async (string? state, AppDbContext db) =>
        {
            var query = db.Alerts.AsNoTracking().AsQueryable();
            if (!string.Equals(state, "all", StringComparison.OrdinalIgnoreCase))
            {
                query = query.Where(alert => alert.State != AlertState.Resolved);
            }

            var alerts = await query.OrderByDescending(alert => alert.CreatedAt).Take(300).ToListAsync();
            return Results.Json(alerts);
        });

        api.MapPost("/alerts/{id:long}/acknowledge", async (long id, AppDbContext db) =>
        {
            var alert = await db.Alerts.FirstOrDefaultAsync(item => item.Id == id);
            if (alert is null)
            {
                return Results.NotFound();
            }

            if (alert.State == AlertState.Open)
            {
                alert.State = AlertState.Acknowledged;
                alert.AcknowledgedAt = DateTime.UtcNow;
                await db.SaveChangesAsync();
            }

            return Results.Json(alert);
        });

        api.MapPost("/alerts/{id:long}/resolve", async (long id, AppDbContext db) =>
        {
            var alert = await db.Alerts.FirstOrDefaultAsync(item => item.Id == id);
            if (alert is null)
            {
                return Results.NotFound();
            }

            if (alert.State != AlertState.Resolved)
            {
                alert.State = AlertState.Resolved;
                alert.ResolvedAt = DateTime.UtcNow;
                await db.SaveChangesAsync();
            }

            return Results.Json(alert);
        });

        api.MapGet("/traps", async (int? take, AppDbContext db) =>
        {
            var count = Math.Clamp(take ?? 200, 1, 500);
            var traps = await db.Traps.AsNoTracking().OrderByDescending(trap => trap.ReceivedAt).Take(count).ToListAsync();
            return Results.Json(traps);
        });

        api.MapGet("/rules", async (AppDbContext db) =>
            Results.Json(await db.Rules.AsNoTracking().OrderBy(rule => rule.Name).ToListAsync()));

        api.MapPost("/rules", async (RuleInput input, RuleService rules) =>
        {
            var (rule, errors) = await rules.SaveAsync(input);
            return errors.Count == 0 ? Results.Json(rule, statusCode: StatusCodes.Status201Created) : Results.BadRequest(new { errors });
        });

        api.MapDelete("/rules/{id:int}", async (int id, RuleService rules) =>
        {
            await rules.DeleteAsync(id);
            return Results.NoContent();
        });

        api.MapGet("/settings", async (AppDbContext db) =>
        {
            var settings = await db.Settings.AsNoTracking().OrderBy(item => item.Id).FirstAsync();
            return Results.Json(SettingsJson(settings, includePassword: false));
        });

        api.MapPut("/settings", async (SettingsUpdate update, AppDbContext db, TrapWorker traps) =>
        {
            var errors = ValidateSettings(update);
            if (errors.Count > 0)
            {
                return Results.BadRequest(new { errors });
            }

            var settings = await db.Settings.OrderBy(item => item.Id).FirstAsync();
            Apply(settings, update);
            await db.SaveChangesAsync();
            await traps.ReconfigureAsync();
            return Results.Json(SettingsJson(settings, includePassword: false));
        });

        api.MapPost("/settings/test-email", async (EmailNotifier email) =>
        {
            try
            {
                await email.SendTestAsync(CancellationToken.None);
                return Results.Json(new { sent = true });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { errors = new[] { ex.Message } });
            }
        });
    }

    private static object HaJson(Device device)
    {
        var ha = HaStatus.FromStored(device.HaState, device.HaPeerState, device.HaVendor, device.LastSnmpOk == true);
        return new { label = ha.Label, css = ha.CssClass, peer = ha.Peer, vendor = ha.Vendor, state = ha.Token };
    }

    private static object Summary(Device device, ResolvedPolicy? resolved = null) => new
    {
        device.Id,
        device.Name,
        device.Host,
        port = resolved?.Port.Value ?? device.Port ?? 161,
        version = TextFormat.Version(resolved?.Version.Value ?? device.Version ?? SnmpVersion.V2C),
        pollIntervalSeconds = resolved?.PollIntervalSeconds.Value ?? device.PollIntervalSeconds ?? 60,
        device.Enabled,
        device.LastPingOk,
        device.LastSnmpOk,
        device.LastResponseMs,
        device.LastSysName,
        device.LastSysDescr,
        uptime = TextFormat.Uptime(device.LastSysUpTimeTicks),
        device.LastPollAt,
        device.LastError,
        status = TextFormat.Reachability(device)
    };

    private static object InterfaceJson(InterfaceState state) => new
    {
        state.IfIndex,
        state.IfDescr,
        state.IfName,
        state.IfAlias,
        state.AdminStatus,
        admin = TextFormat.Admin(state.AdminStatus),
        state.OperStatus,
        oper = TextFormat.Oper(state.OperStatus),
        speed = TextFormat.Speed(state.SpeedBps),
        inBps = state.InBps,
        outBps = state.OutBps,
        inText = TextFormat.Bps(state.InBps),
        outText = TextFormat.Bps(state.OutBps),
        inUtil = state.InUtil,
        outUtil = state.OutUtil,
        state.Monitored,
        monitorOverride = state.MonitorOverride,
        followsRules = state.MonitorOverride is null,
        state.UpdatedAt
    };

    private static object SettingsJson(AppSetting settings, bool includePassword) => new
    {
        settings.RetentionDays,
        settings.FailureThreshold,
        settings.TrapEnabled,
        settings.TrapPort,
        settings.SmtpEnabled,
        settings.SmtpHost,
        settings.SmtpPort,
        settings.SmtpUser,
        smtpPasswordSet = !string.IsNullOrEmpty(settings.SmtpPassword),
        smtpPassword = includePassword ? settings.SmtpPassword : null,
        settings.SmtpFrom,
        settings.SmtpTo,
        settings.SmtpSecurity
    };

    private static void Apply(AppSetting settings, SettingsUpdate update)
    {
        settings.RetentionDays = update.RetentionDays;
        settings.FailureThreshold = update.FailureThreshold;
        settings.TrapEnabled = update.TrapEnabled;
        settings.TrapPort = update.TrapPort;
        settings.SmtpEnabled = update.SmtpEnabled;
        settings.SmtpHost = (update.SmtpHost ?? "").Trim();
        settings.SmtpPort = update.SmtpPort;
        settings.SmtpUser = (update.SmtpUser ?? "").Trim();
        if (!string.IsNullOrEmpty(update.SmtpPassword))
        {
            settings.SmtpPassword = update.SmtpPassword;
        }

        settings.SmtpFrom = (update.SmtpFrom ?? "").Trim();
        settings.SmtpTo = (update.SmtpTo ?? "").Trim();
        settings.SmtpSecurity = string.IsNullOrWhiteSpace(update.SmtpSecurity) ? "StartTls" : update.SmtpSecurity.Trim();
    }

    private static List<string> ValidateSettings(SettingsUpdate update)
    {
        var errors = new List<string>();
        if (update.RetentionDays is < 1 or > 3650)
        {
            errors.Add("Retention must be between 1 and 3650 days.");
        }

        if (update.FailureThreshold is < 1 or > 20)
        {
            errors.Add("Failure threshold must be between 1 and 20 polls.");
        }

        if (update.TrapPort is < 1 or > 65535)
        {
            errors.Add("Trap port must be between 1 and 65535.");
        }

        if (update.SmtpPort is < 1 or > 65535)
        {
            errors.Add("SMTP port must be between 1 and 65535.");
        }

        if (update.SmtpSecurity is not ("None" or "StartTls" or "SslOnConnect" or null or ""))
        {
            errors.Add("SMTP security must be None, StartTls, or SslOnConnect.");
        }

        return errors;
    }

    private static async Task<string> ReadCsvAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken);
            var file = form.Files.GetFile("file");
            if (file is not null)
            {
                using var reader = new StreamReader(file.OpenReadStream());
                return await reader.ReadToEndAsync(cancellationToken);
            }

            return form["csv"].ToString();
        }

        using var body = new StreamReader(request.Body);
        return await body.ReadToEndAsync(cancellationToken);
    }

    private static int ClampMinutes(int? minutes) => Math.Clamp(minutes ?? 60, 5, 10080);

    private static List<ChartPoint> Downsample(List<ChartPoint> points, int max = 360)
    {
        if (points.Count <= max)
        {
            return points.Select(Stamp).ToList();
        }

        var size = (int)Math.Ceiling(points.Count / (double)max);
        var result = new List<ChartPoint>();
        for (var index = 0; index < points.Count; index += size)
        {
            var bucket = points.Skip(index).Take(size).ToList();
            var last = bucket[^1];
            result.Add(Stamp(new ChartPoint(
                last.T,
                Average(bucket.Select(point => point.InBps)),
                Average(bucket.Select(point => point.OutBps)),
                Average(bucket.Select(point => point.InUtil)),
                Average(bucket.Select(point => point.OutUtil)),
                last.OperStatus,
                AverageInt(bucket.Select(point => point.ResponseMs)),
                Average(bucket.Select(point => point.Value)),
                Average(bucket.Select(point => point.Rate)))));
        }

        return result;
    }

    private static ChartPoint Stamp(ChartPoint point)
    {
        var time = point.T.Kind == DateTimeKind.Utc ? point.T : DateTime.SpecifyKind(point.T, DateTimeKind.Utc);
        return point with { T = time };
    }

    private static double? Average(IEnumerable<double?> values)
    {
        var numbers = values.Where(value => value is not null).Select(value => value!.Value).ToList();
        return numbers.Count == 0 ? null : numbers.Average();
    }

    private static int? AverageInt(IEnumerable<int?> values)
    {
        var numbers = values.Where(value => value is not null).Select(value => value!.Value).ToList();
        return numbers.Count == 0 ? null : (int)Math.Round(numbers.Average());
    }

    private sealed record ChartPoint(
        DateTime T,
        double? InBps,
        double? OutBps,
        double? InUtil,
        double? OutUtil,
        int? OperStatus,
        int? ResponseMs,
        double? Value,
        double? Rate);
}

public sealed class SettingsUpdate
{
    public int RetentionDays { get; set; }
    public int FailureThreshold { get; set; }
    public bool TrapEnabled { get; set; }
    public int TrapPort { get; set; }
    public bool SmtpEnabled { get; set; }
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public string? SmtpUser { get; set; }
    public string? SmtpPassword { get; set; }
    public string? SmtpFrom { get; set; }
    public string? SmtpTo { get; set; }
    public string? SmtpSecurity { get; set; }
}
