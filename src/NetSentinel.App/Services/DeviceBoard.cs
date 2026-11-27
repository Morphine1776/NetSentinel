using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using NetSentinel;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed record DeviceBoardRow(
    int Id,
    string Name,
    string Host,
    int Port,
    string Location,
    string Version,
    int PollIntervalSeconds,
    string Status,
    string Lamp,
    string SysName,
    string Uptime,
    string Response,
    string Ping,
    string LastPoll,
    string LastError,
    bool Down,
    string HaLabel,
    string HaClass,
    string HaPeer);

public sealed record DeviceBoardGroup(
    string Key,
    string Name,
    string Health,
    string Cue,
    int Total,
    int Reporting,
    int Down,
    int Pending,
    int Paused,
    IReadOnlyList<DeviceBoardRow> Devices);

public sealed record DeviceBoard(
    int Reachable,
    int Down,
    int Waiting,
    int Watched,
    IReadOnlyList<DeviceBoardGroup> Groups);

public static class DeviceBoardBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.Default
    };

    public static async Task<DeviceBoard> LoadAsync(AppDbContext db, CancellationToken cancellationToken = default)
    {
        var devices = await db.Devices.AsNoTracking().ToListAsync(cancellationToken);
        var catalog = await PolicyStore.LoadAsync(db, cancellationToken);
        var critical = await db.Alerts.AsNoTracking()
            .Where(alert => alert.DeviceId != null
                && alert.State != AlertState.Resolved
                && alert.Severity == AlertSeverity.Critical)
            .Select(alert => alert.DeviceId!.Value)
            .Distinct()
            .ToListAsync(cancellationToken);
        return Build(devices, critical.ToHashSet(), catalog);
    }

    public static DeviceBoard Build(IReadOnlyList<Device> devices, IReadOnlySet<int> criticalDeviceIds, PolicyCatalog? catalog = null)
    {
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(criticalDeviceIds);

        var reachable = 0;
        var down = 0;
        var waiting = 0;
        var inputs = new List<LocationDeviceInput>(devices.Count);
        foreach (var device in devices)
        {
            var presence = LocationGroups.Presence(device.Enabled, device.LastPollAt != null, device.LastSnmpOk == true);
            if (presence == DevicePresence.Reporting)
            {
                reachable++;
            }
            else if (presence == DevicePresence.Down)
            {
                down++;
            }
            else
            {
                waiting++;
            }

            inputs.Add(new LocationDeviceInput(
                device.Id,
                device.Name,
                device.Host,
                device.Location,
                presence,
                criticalDeviceIds.Contains(device.Id)));
        }

        var byId = devices.ToDictionary(device => device.Id);
        var groups = LocationGroups.Group(inputs).Select(group =>
        {
            var rows = group.DeviceIds.Select(id => Row(byId[id], catalog)).ToList();
            return new DeviceBoardGroup(
                group.Key,
                group.Name,
                group.Health.ToString().ToLowerInvariant(),
                group.Cue,
                group.Total,
                group.Reporting,
                group.Down,
                group.Pending,
                group.Paused,
                rows);
        }).ToList();

        return new DeviceBoard(reachable, down, waiting, devices.Count, groups);
    }

    public static string ToJson(DeviceBoard board) => JsonSerializer.Serialize(board, JsonOptions);

    private static DeviceBoardRow Row(Device device, PolicyCatalog? catalog)
    {
        var resolved = catalog?.Resolve(device);
        var ha = HaStatus.FromStored(device.HaState, device.HaPeerState, device.HaVendor, device.LastSnmpOk == true);
        var label = string.IsNullOrWhiteSpace(ha.Label) ? "N/A" : ha.Label;
        var peer = string.IsNullOrWhiteSpace(ha.Peer) ? "" : "Peer " + ha.Peer;
        return new DeviceBoardRow(
            device.Id,
            device.Name,
            device.Host,
            resolved?.Port.Value ?? device.Port ?? 161,
            (device.Location ?? "").Trim(),
            TextFormat.Version(resolved?.Version.Value ?? device.Version ?? SnmpVersion.V2C),
            resolved?.PollIntervalSeconds.Value ?? device.PollIntervalSeconds ?? 60,
            TextFormat.Reachability(device),
            TextFormat.Lamp(device),
            device.LastSysName ?? "—",
            TextFormat.Uptime(device.LastSysUpTimeTicks),
            TextFormat.Ms(device.LastResponseMs),
            TextFormat.Ping(device.LastPingOk),
            TextFormat.When(device.LastPollAt),
            device.LastError ?? "",
            TextFormat.Reachability(device) == "Down",
            label,
            string.IsNullOrWhiteSpace(ha.CssClass) ? "ha-na" : ha.CssClass,
            peer);
    }
}
