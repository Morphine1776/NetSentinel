using System.Globalization;
using System.Text;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class ImportCommitResult
{
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Skipped { get; set; }
    public int Rejected { get; set; }
    public string? Error { get; set; }
}

public sealed class ImportService
{
    private readonly AppDbContext _db;
    private readonly InterfaceMonitorService _interfaces;

    public ImportService(AppDbContext db, InterfaceMonitorService interfaces)
    {
        _db = db;
        _interfaces = interfaces;
    }

    public async Task<CsvPreview> PreviewAsync(string? csv, CancellationToken cancellationToken = default)
    {
        var existing = await LoadExistingAsync(cancellationToken);
        return CsvDevices.Preview(csv, existing);
    }

    public async Task<string> ExportAsync(CancellationToken cancellationToken = default)
    {
        var devices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync(cancellationToken);
        var names = devices.ToDictionary(device => device.Id, device => device.Name);
        var rows = devices.Select(device => new CsvDeviceRow(
            0,
            device.Name,
            device.Host,
            device.Version is SnmpVersion version ? TextFormat.Version(version) : "",
            device.Community ?? "",
            device.V3User ?? "",
            device.V3AuthProtocol ?? "",
            device.V3AuthPassword is null ? "" : "set",
            device.V3PrivProtocol ?? "",
            device.V3PrivPassword is null ? "" : "set",
            device.PollIntervalSeconds?.ToString(CultureInfo.InvariantCulture) ?? "",
            device.Port?.ToString(CultureInfo.InvariantCulture) ?? "",
            device.GroupName,
            device.Location,
            device.Tags,
            device.ParentDeviceId is int parentId && names.TryGetValue(parentId, out var parent) ? parent : "",
            device.IfIncludePattern,
            device.IfExcludePattern,
            device.IfPatternSyntax,
            device.IfExcludeAdminDown is bool excludeAdmin ? Flag(excludeAdmin) : "",
            device.IfRequireAlias is bool requireAlias ? Flag(requireAlias) : "",
            device.IfMatchFields,
            device.TimeoutMs?.ToString(CultureInfo.InvariantCulture),
            device.Retries?.ToString(CultureInfo.InvariantCulture),
            device.UnmonitorDown is bool unmonitor ? Flag(unmonitor) : "",
            device.AlertOnHaChange is bool alertHa ? Flag(alertHa) : ""));
        return CsvDevices.Export(rows);
    }

    public async Task<ImportCommitResult> CommitAsync(string? csv, string? duplicateMode, CancellationToken cancellationToken = default)
    {
        var mode = string.Equals(duplicateMode, "update", StringComparison.OrdinalIgnoreCase) ? "update" : "skip";
        var preview = await PreviewAsync(csv, cancellationToken);
        if (preview.FileError is not null)
        {
            return new ImportCommitResult { Error = preview.FileError };
        }

        var parsed = CsvDevices.Parse(csv!);
        var byLine = parsed.ToDictionary(row => row.Line);
        var result = new ImportCommitResult { Rejected = preview.Errors };
        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        var touched = new List<(CsvDeviceRow Row, Device Device)>();

        foreach (var item in preview.Rows)
        {
            if (item.Status == CsvRowStatus.Error || !byLine.TryGetValue(item.Line, out var row))
            {
                continue;
            }

            if (item.Status == CsvRowStatus.Duplicate)
            {
                if (mode == "skip" || item.ExistingDeviceId is not int existingId)
                {
                    result.Skipped++;
                    continue;
                }

                var device = await _db.Devices.FirstAsync(entity => entity.Id == existingId, cancellationToken);
                Apply(device, row, keepSecrets: true);
                touched.Add((row, device));
                result.Updated++;
                continue;
            }

            var created = new Device { CreatedAt = DateTime.UtcNow };
            Apply(created, row, keepSecrets: false);
            _db.Devices.Add(created);
            touched.Add((row, created));
            result.Created++;
        }

        await _db.SaveChangesAsync(cancellationToken);

        var catalog = await _db.Devices.ToListAsync(cancellationToken);
        foreach (var (row, device) in touched)
        {
            if (string.IsNullOrWhiteSpace(row.Parent))
            {
                continue;
            }

            var parent = Find(catalog, row.Parent.Trim());
            if (parent is null || parent.Id == device.Id)
            {
                continue;
            }

            device.ParentDeviceId = parent.Id;
        }

        await PolicyStore.EnsureLocationsAsync(_db, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        foreach (var (_, device) in touched)
        {
            await _interfaces.ReapplyAsync(device.Id, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static string Flag(bool value) => value ? "yes" : "no";

    private static void Apply(Device device, CsvDeviceRow row, bool keepSecrets)
    {
        device.Name = row.Name.Trim();
        device.Host = row.Host.Trim();
        device.Port = BlankInt(row.Port);
        device.Version = string.IsNullOrWhiteSpace(row.Version) ? null : CsvDevices.TryParseVersion(row.Version, out var version) ? version : device.Version;
        device.PollIntervalSeconds = BlankInt(row.PollInterval);
        device.TimeoutMs = OptionalInt(row.TimeoutMs, device.TimeoutMs);
        device.Retries = OptionalInt(row.Retries, device.Retries);
        device.GroupName = row.Group.Trim();
        device.Location = row.Location.Trim();
        device.Tags = CsvDevices.NormalizeTags(row.Tags);
        ApplyInterfacePolicy(device, row);
        device.Enabled = true;
        device.UpdatedAt = DateTime.UtcNow;
        device.NextPollAt = DateTime.UtcNow;
        device.Community = string.IsNullOrWhiteSpace(row.Community) ? null : row.Community.Trim();
        device.V3User = string.IsNullOrWhiteSpace(row.V3User) ? null : row.V3User.Trim();
        device.V3AuthProtocol = string.IsNullOrWhiteSpace(row.V3AuthProtocol) ? null : row.V3AuthProtocol.Trim();
        device.V3PrivProtocol = string.IsNullOrWhiteSpace(row.V3PrivProtocol) ? null : row.V3PrivProtocol.Trim();
        device.V3AuthPassword = SecretCell(row.V3AuthPassword, device.V3AuthPassword, keepSecrets);
        device.V3PrivPassword = SecretCell(row.V3PrivPassword, device.V3PrivPassword, keepSecrets);
        device.UnmonitorDown = OptionalFlag(row.UnmonitorDown, device.UnmonitorDown);
        device.AlertOnHaChange = OptionalFlag(row.AlertOnHa, device.AlertOnHaChange);
    }

    private static int? BlankInt(string? text)
        => string.IsNullOrWhiteSpace(text) ? null : int.Parse(text, CultureInfo.InvariantCulture);

    private static int? OptionalInt(string? text, int? current)
    {
        if (text is null)
        {
            return current;
        }

        return string.IsNullOrWhiteSpace(text) ? null : int.Parse(text, CultureInfo.InvariantCulture);
    }

    private static bool? OptionalFlag(string? text, bool? current)
    {
        if (text is null)
        {
            return current;
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        return CsvDevices.TryParseFlag(text, out var value) ? value : current;
    }

    private static string? SecretCell(string posted, string? current, bool keepSecrets)
    {
        if (string.IsNullOrEmpty(posted))
        {
            return null;
        }

        if (posted.Equals("set", StringComparison.OrdinalIgnoreCase) || posted.Equals("keep", StringComparison.OrdinalIgnoreCase))
        {
            return keepSecrets ? current : null;
        }

        return posted;
    }

    private static void ApplyInterfacePolicy(Device device, CsvDeviceRow row)
    {
        if (row.IfInclude is not null)
        {
            device.IfIncludePattern = string.IsNullOrWhiteSpace(row.IfInclude) ? null : row.IfInclude.Trim();
        }

        if (row.IfExclude is not null)
        {
            device.IfExcludePattern = string.IsNullOrWhiteSpace(row.IfExclude) ? null : row.IfExclude.Trim();
        }

        if (row.IfPattern is not null)
        {
            device.IfPatternSyntax = string.IsNullOrWhiteSpace(row.IfPattern) ? null : row.IfPattern.Trim().ToLowerInvariant();
        }

        if (row.IfMatch is not null)
        {
            device.IfMatchFields = string.IsNullOrWhiteSpace(row.IfMatch) || !InterfaceMonitor.TryParseFields(row.IfMatch, out var name, out var descr, out var alias)
                ? null
                : InterfaceMonitor.FormatFields(name, descr, alias);
        }

        if (row.IfExcludeAdminDown is not null)
        {
            device.IfExcludeAdminDown = string.IsNullOrWhiteSpace(row.IfExcludeAdminDown) || !CsvDevices.TryParseFlag(row.IfExcludeAdminDown, out var excludeAdminDown)
                ? null
                : excludeAdminDown;
        }

        if (row.IfRequireAlias is not null)
        {
            device.IfRequireAlias = string.IsNullOrWhiteSpace(row.IfRequireAlias) || !CsvDevices.TryParseFlag(row.IfRequireAlias, out var requireAlias)
                ? null
                : requireAlias;
        }
    }

    private static Device? Find(IEnumerable<Device> devices, string token)
    {
        return devices.FirstOrDefault(device =>
            string.Equals(device.Name, token, StringComparison.OrdinalIgnoreCase)
            || string.Equals(device.Host.Trim().TrimEnd('.'), token.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase));
    }

    private async Task<List<ExistingDeviceRef>> LoadExistingAsync(CancellationToken cancellationToken)
    {
        var devices = await _db.Devices.AsNoTracking().ToListAsync(cancellationToken);
        var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
        return devices.Select(device => new ExistingDeviceRef(
            device.Id,
            device.Name,
            device.Host,
            catalog.Resolve(device).Port.Value,
            device.ParentDeviceId)).ToList();
    }
}

public sealed class MapService
{
    private readonly AppDbContext _db;

    public MapService(AppDbContext db)
    {
        _db = db;
    }

    public async Task<object> BuildAsync(bool showUnmonitored = false, CancellationToken cancellationToken = default)
    {
        var devices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync(cancellationToken);
        var links = await _db.Links.AsNoTracking().ToListAsync(cancellationToken);
        var monitored = await _db.InterfaceStates.AsNoTracking()
            .Select(state => new { state.DeviceId, state.IfIndex, state.Monitored })
            .ToListAsync(cancellationToken);
        var monitoredByPort = monitored.ToDictionary(state => (state.DeviceId, state.IfIndex), state => state.Monitored);
        var nodes = devices.Select(device => new
        {
            id = device.Id,
            name = device.Name,
            host = device.Host,
            port = device.Port ?? 161,
            group = device.GroupName,
            location = device.Location,
            tags = device.Tags,
            status = TextFormat.Reachability(device),
            lamp = TextFormat.Lamp(device),
            sysName = device.LastSysName,
            parentId = device.ParentDeviceId,
            x = device.MapX,
            y = device.MapY
        });

        var edges = new List<object>();
        var folded = new Dictionary<string, FoldedEdge>(StringComparer.Ordinal);
        void Add(int left, int right, string kind, string localPort, string remotePort, double? utilization, int? linkId, bool removable)
        {
            if (left == right) return;
            var key = left < right ? $"{left}:{right}" : $"{right}:{left}";
            if (!folded.TryGetValue(key, out var edge))
            {
                edge = new FoldedEdge(left, right);
                folded[key] = edge;
            }

            edge.Kinds.Add(kind);
            if (utilization is double value && (edge.Utilization is null || value > edge.Utilization))
            {
                edge.Utilization = value;
                edge.LocalPort = localPort;
                edge.RemotePort = remotePort;
            }
            else if (string.IsNullOrEmpty(edge.LocalPort) && !string.IsNullOrEmpty(localPort))
            {
                edge.LocalPort = localPort;
                edge.RemotePort = remotePort;
            }

            if (removable && edge.ManualId is null)
            {
                edge.ManualId = linkId;
            }
        }

        foreach (var link in links)
        {
            var utilization = link.Utilization;
            if (!showUnmonitored
                && link.LocalIfIndex is int ifIndex
                && monitoredByPort.TryGetValue((link.SourceDeviceId, ifIndex), out var isMonitored)
                && !isMonitored)
            {
                utilization = null;
            }

            Add(link.SourceDeviceId, link.TargetDeviceId, link.Kind, link.LocalPort, link.RemotePort, utilization, link.Id, link.Kind == "manual");
        }

        foreach (var device in devices)
        {
            if (device.ParentDeviceId is int parentId && devices.Any(item => item.Id == parentId))
            {
                Add(device.Id, parentId, "parent", "", "", null, null, false);
            }
        }

        foreach (var edge in folded.Values)
        {
            edges.Add(new
            {
                source = edge.Left,
                target = edge.Right,
                kinds = edge.Kinds.OrderBy(kind => kind).ToArray(),
                label = Label(edge),
                utilization = edge.Utilization,
                localPort = edge.LocalPort,
                remotePort = edge.RemotePort,
                manualId = edge.ManualId
            });
        }

        return new { nodes, edges };
    }

    public async Task SavePositionsAsync(IReadOnlyList<MapPosition> positions, CancellationToken cancellationToken)
    {
        var ids = positions.Select(position => position.Id).ToHashSet();
        var devices = await _db.Devices.Where(device => ids.Contains(device.Id)).ToListAsync(cancellationToken);
        foreach (var device in devices)
        {
            var position = positions.First(item => item.Id == device.Id);
            device.MapX = position.X;
            device.MapY = position.Y;
        }

        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<(DeviceLink? Link, string? Error)> AddManualLinkAsync(int fromId, int toId, CancellationToken cancellationToken)
    {
        if (fromId == toId)
        {
            return (null, "Choose two different devices.");
        }

        var count = await _db.Devices.CountAsync(device => device.Id == fromId || device.Id == toId, cancellationToken);
        if (count != 2)
        {
            return (null, "Both devices must already be in the inventory.");
        }

        var existing = await _db.Links.FirstOrDefaultAsync(
            link => link.Kind == "manual" && ((link.SourceDeviceId == fromId && link.TargetDeviceId == toId) || (link.SourceDeviceId == toId && link.TargetDeviceId == fromId)),
            cancellationToken);
        if (existing is not null)
        {
            return (existing, null);
        }

        var link = new DeviceLink
        {
            SourceDeviceId = fromId,
            TargetDeviceId = toId,
            Kind = "manual",
            UpdatedAt = DateTime.UtcNow
        };
        _db.Links.Add(link);
        await _db.SaveChangesAsync(cancellationToken);
        return (link, null);
    }

    public async Task<bool> DeleteManualLinkAsync(int id, CancellationToken cancellationToken)
    {
        var link = await _db.Links.FirstOrDefaultAsync(item => item.Id == id && item.Kind == "manual", cancellationToken);
        if (link is null)
        {
            return false;
        }

        _db.Links.Remove(link);
        await _db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static string Label(FoldedEdge edge)
    {
        var builder = new StringBuilder(string.Join(" · ", edge.Kinds.OrderBy(kind => kind)));
        if (edge.Utilization is double utilization)
        {
            builder.Append(' ');
            builder.Append(utilization.ToString("0.#", CultureInfo.InvariantCulture));
            builder.Append('%');
        }

        return builder.ToString();
    }

    private sealed class FoldedEdge
    {
        public FoldedEdge(int left, int right)
        {
            Left = left;
            Right = right;
        }

        public int Left { get; }
        public int Right { get; }
        public HashSet<string> Kinds { get; } = new(StringComparer.Ordinal);
        public double? Utilization { get; set; }
        public string LocalPort { get; set; } = "";
        public string RemotePort { get; set; } = "";
        public int? ManualId { get; set; }
    }
}

public sealed class MapPosition
{
    public int Id { get; set; }
    public double X { get; set; }
    public double Y { get; set; }
}

public sealed class MapPositionBatch
{
    public List<MapPosition> Positions { get; set; } = new();
}

public sealed class ManualLinkRequest
{
    public int FromId { get; set; }
    public int ToId { get; set; }
}

public sealed class ImportCommitRequest
{
    public string? Csv { get; set; }
    public string? DuplicateMode { get; set; }
}
