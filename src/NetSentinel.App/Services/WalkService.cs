using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Snmp;

namespace NetSentinel.Services;

public sealed class WalkQuery
{
    public string? BaseOid { get; set; }
    public int? MaxRows { get; set; }
}

public sealed class WalkDraft
{
    public string? Host { get; set; }
    public string? Location { get; set; }
    public string? V3Context { get; set; }
    public int? DeviceId { get; set; }
    public string? BaseOid { get; set; }
    public int? MaxRows { get; set; }
    public PolicyForm? Policy { get; set; }
}

public sealed class WalkService
{
    private readonly AppDbContext _db;
    private readonly SnmpWalkClient _walks;

    public WalkService(AppDbContext db, SnmpWalkClient walks)
    {
        _db = db;
        _walks = walks;
    }

    public async Task<IResult> WalkDeviceAsync(int id, WalkQuery? query, CancellationToken cancellationToken)
    {
        var device = await _db.Devices.AsNoTracking().FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (device is null)
        {
            return Results.NotFound();
        }

        var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
        var resolved = catalog.Resolve(device);
        return await RunAsync(device.Host, device.V3Context, resolved, query?.BaseOid, query?.MaxRows, cancellationToken);
    }

    public async Task<IResult> WalkDraftAsync(WalkDraft? draft, CancellationToken cancellationToken)
    {
        draft ??= new WalkDraft();
        var host = (draft.Host ?? "").Trim();
        if (host.Length is < 1 or > 255)
        {
            return Results.BadRequest(new { errors = new[] { "Enter a host or IP before walking." } });
        }

        Device? existing = null;
        if (draft.DeviceId is int id)
        {
            existing = await _db.Devices.AsNoTracking().FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
            if (existing is null)
            {
                return Results.NotFound();
            }
        }

        var current = existing is null ? new PolicyValues() : PolicyStore.FromDevice(existing);
        var written = PolicyStore.ApplyForm(current, draft.Policy ?? new PolicyForm(), inheritAllowed: true);
        var preview = new Device
        {
            Location = (draft.Location ?? existing?.Location ?? "").Trim(),
            Version = written.Version,
            Community = written.Community,
            V3User = written.V3User,
            V3AuthProtocol = written.V3AuthProtocol,
            V3AuthPassword = written.V3AuthSecret,
            V3PrivProtocol = written.V3PrivProtocol,
            V3PrivPassword = written.V3PrivSecret,
            Port = written.Port,
            PollIntervalSeconds = written.PollIntervalSeconds,
            TimeoutMs = written.TimeoutMs,
            Retries = written.Retries,
            IfIncludePattern = written.IfIncludePattern,
            IfExcludePattern = written.IfExcludePattern,
            IfPatternSyntax = written.IfPatternSyntax,
            IfMatchFields = written.IfMatchFields,
            IfExcludeAdminDown = written.ExcludeAdminDown,
            IfRequireAlias = written.RequireAlias,
            UnmonitorDown = written.UnmonitorDown,
            AlertOnHaChange = written.AlertOnHaChange
        };
        var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
        var resolved = catalog.Resolve(preview);
        var errors = PolicyStore.Validate(resolved, written, requireConcrete: false);
        if (errors.Count > 0)
        {
            return Results.BadRequest(new { errors });
        }

        var context = draft.V3Context ?? existing?.V3Context ?? "";
        return await RunAsync(host, context, resolved, draft.BaseOid, draft.MaxRows, cancellationToken);
    }

    private async Task<IResult> RunAsync(
        string host,
        string? context,
        ResolvedPolicy resolved,
        string? baseOid,
        int? maxRows,
        CancellationToken cancellationToken)
    {
        var rows = SnmpWalkLogic.NormalizeMaxRows(maxRows);
        if (rows is null)
        {
            return Results.BadRequest(new { errors = new[] { $"Max rows must be between 1 and {SnmpWalkLogic.MaxRowsLimit}." } });
        }

        var oid = SnmpWalkLogic.Normalize(baseOid);
        if (!SnmpWalkLogic.IsOid(oid))
        {
            return Results.BadRequest(new { errors = new[] { "Enter a numeric OID such as 1.3.6.1.2.1.1." } });
        }

        var target = new DevicePollTarget(
            host.Trim(),
            resolved.Port.Value,
            resolved.Version.Value,
            resolved.Community.Value ?? "",
            resolved.V3User.Value ?? "",
            context ?? "",
            resolved.V3AuthProtocol.Value ?? "None",
            resolved.V3AuthSecret.Value ?? "",
            resolved.V3PrivProtocol.Value ?? "None",
            resolved.V3PrivSecret.Value ?? "",
            Array.Empty<CustomOidTarget>(),
            resolved.TimeoutMs.Value,
            resolved.Retries.Value);

        WalkResult result;
        try
        {
            result = await _walks.WalkAsync(target, oid, rows.Value, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return Results.Json(new { errors = new[] { "SNMP walk failed." } }, statusCode: StatusCodes.Status502BadGateway);
        }

        if (!result.Ok)
        {
            var error = string.IsNullOrWhiteSpace(result.Error) ? "SNMP walk failed." : result.Error;
            if (error.Contains("timed out", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new { errors = new[] { error } }, statusCode: StatusCodes.Status504GatewayTimeout);
            }

            if (error.Contains("noSuch", StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(new { errors = new[] { error } });
            }

            return Results.Json(new { errors = new[] { error } }, statusCode: StatusCodes.Status502BadGateway);
        }

        return Results.Json(new
        {
            baseOid = result.BaseOid,
            truncated = result.Truncated,
            limit = result.Limit,
            message = result.Message,
            maxRows = result.MaxRows,
            rows = result.Rows.Select(row => new
            {
                oid = row.Oid,
                type = row.Type,
                value = row.Value,
                numeric = row.Numeric,
                kind = row.Kind,
                label = row.Label,
                sensorType = row.SensorType,
                scale = row.Scale,
                suggestedName = row.SuggestedName,
                unit = row.Unit
            })
        });
    }
}
