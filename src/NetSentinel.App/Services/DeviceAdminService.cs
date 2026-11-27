using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class CustomOidInput
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Oid { get; set; } = "";
    public string? Unit { get; set; }
}

public sealed class DeviceInput
{
    public int? Id { get; set; }
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 161;
    public SnmpVersion Version { get; set; } = SnmpVersion.V2C;
    public string? Community { get; set; } = "public";
    public string? V3User { get; set; }
    public string? V3Context { get; set; }
    public string? V3AuthProtocol { get; set; } = "None";
    public string? V3AuthPassword { get; set; }
    public string? V3PrivProtocol { get; set; } = "None";
    public string? V3PrivPassword { get; set; }
    public int PollIntervalSeconds { get; set; } = 60;
    public bool Enabled { get; set; } = true;
    public string? GroupName { get; set; }
    public string? Location { get; set; }
    public string? Tags { get; set; }
    public int? ParentDeviceId { get; set; }
    public List<CustomOidInput> CustomOids { get; set; } = new();
}

public sealed class DeviceSaveResult
{
    public Device? Device { get; init; }
    public List<string> Errors { get; init; } = new();
    public bool Ok => Errors.Count == 0;
}

public sealed class DeviceAdminService
{
    private static readonly HashSet<string> AuthProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "None", "MD5", "SHA1", "SHA256", "SHA384", "SHA512"
    };

    private static readonly HashSet<string> PrivProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "None", "DES", "AES", "AES192", "AES256"
    };

    private readonly AppDbContext _db;

    public DeviceAdminService(AppDbContext db)
    {
        _db = db;
    }

    public Task<DeviceSaveResult> SaveAsync(DeviceInput input, CancellationToken cancellationToken = default)
        => SaveAsync(input, null, cancellationToken);

    public async Task<DeviceSaveResult> SaveAsync(DeviceInput input, PolicyForm? policy, CancellationToken cancellationToken = default)
    {
        var errors = new List<string>();
        input.Name = (input.Name ?? "").Trim();
        input.Host = (input.Host ?? "").Trim();
        input.Community = string.IsNullOrWhiteSpace(input.Community) ? null : input.Community.Trim();
        input.V3User = (input.V3User ?? "").Trim();
        input.V3Context = (input.V3Context ?? "").Trim();
        input.V3AuthProtocol = Normalize(input.V3AuthProtocol, "None");
        input.V3PrivProtocol = Normalize(input.V3PrivProtocol, "None");
        input.CustomOids ??= new List<CustomOidInput>();

        Device? existing = null;
        if (input.Id is int id)
        {
            existing = await _db.Devices.Include(d => d.CustomOids).FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
            if (existing is null)
            {
                errors.Add("That device no longer exists.");
                return new DeviceSaveResult { Errors = errors };
            }

            if (string.IsNullOrEmpty(input.V3AuthPassword))
            {
                input.V3AuthPassword = existing.V3AuthPassword;
            }

            if (string.IsNullOrEmpty(input.V3PrivPassword))
            {
                input.V3PrivPassword = existing.V3PrivPassword;
            }

            if (string.IsNullOrEmpty(input.Community))
            {
                input.Community = existing.Community;
            }
        }

        if (input.Name.Length is < 1 or > 80)
        {
            errors.Add("Name must be 1–80 characters.");
        }

        if ((input.GroupName ?? "").Trim().Length > 80)
        {
            errors.Add("Group must be 80 characters or fewer.");
        }

        if ((input.Location ?? "").Trim().Length > 80)
        {
            errors.Add("Location must be 80 characters or fewer.");
        }

        if ((input.Tags ?? "").Trim().Length > 200)
        {
            errors.Add("Tags must be 200 characters or fewer.");
        }

        if (input.ParentDeviceId is int parentId)
        {
            if (existing?.Id == parentId)
            {
                errors.Add("A device cannot be its own parent.");
            }
            else if (!await _db.Devices.AnyAsync(device => device.Id == parentId, cancellationToken))
            {
                errors.Add("The parent device was not found.");
            }
            else if (existing is not null && await ParentCycleAsync(existing.Id, parentId, cancellationToken))
            {
                errors.Add("That parent would create a cycle.");
            }
        }

        if (input.Host.Length is < 1 or > 255)
        {
            errors.Add("Host must be a hostname or IP address.");
        }

        PolicyValues? written = null;
        if (policy is null)
        {
            if (input.Port is < 1 or > 65535)
            {
                errors.Add("SNMP port must be between 1 and 65535.");
            }

            if (input.PollIntervalSeconds is < 5 or > 86400)
            {
                errors.Add("Poll interval must be between 5 seconds and 24 hours.");
            }

            if (input.Version is SnmpVersion.V1 or SnmpVersion.V2C)
            {
                if (string.IsNullOrWhiteSpace(input.Community) || input.Community.Length > 128)
                {
                    errors.Add("A community string is required for SNMP v1 and v2c.");
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(input.V3User) || input.V3User.Length > 64)
                {
                    errors.Add("An SNMPv3 user name is required.");
                }

                if (!AuthProtocols.Contains(input.V3AuthProtocol))
                {
                    errors.Add("Authentication protocol is not supported.");
                }

                if (!PrivProtocols.Contains(input.V3PrivProtocol))
                {
                    errors.Add("Privacy protocol is not supported.");
                }

                if (!input.V3AuthProtocol.Equals("None", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(input.V3AuthPassword))
                {
                    errors.Add("An authentication password is required for the selected protocol.");
                }
                else if (!input.V3AuthProtocol.Equals("None", StringComparison.OrdinalIgnoreCase) && input.V3AuthPassword!.Length < 8)
                {
                    errors.Add("SNMPv3 authentication passwords must be at least 8 characters.");
                }

                if (!input.V3PrivProtocol.Equals("None", StringComparison.OrdinalIgnoreCase))
                {
                    if (input.V3AuthProtocol.Equals("None", StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add("Privacy requires authentication.");
                    }

                    if (string.IsNullOrEmpty(input.V3PrivPassword))
                    {
                        errors.Add("A privacy password is required for the selected protocol.");
                    }
                    else if (input.V3PrivPassword.Length < 8)
                    {
                        errors.Add("SNMPv3 privacy passwords must be at least 8 characters.");
                    }
                }
            }
        }
        else
        {
            var current = existing is null ? new PolicyValues() : PolicyStore.FromDevice(existing);
            written = PolicyStore.ApplyForm(current, policy, inheritAllowed: true);
            await PolicyStore.EnsureLocationAsync(_db, input.Location, cancellationToken);
            var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
            var preview = new Device
            {
                Location = (input.Location ?? "").Trim(),
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
            errors.AddRange(PolicyStore.Validate(catalog.Resolve(preview), written, requireConcrete: false));
        }

        var oids = input.CustomOids
            .Where(row => !string.IsNullOrWhiteSpace(row.Oid) || !string.IsNullOrWhiteSpace(row.Name))
            .ToList();
        if (oids.Count > 32)
        {
            errors.Add("A device can have at most 32 custom OIDs.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in oids)
        {
            row.Name = (row.Name ?? "").Trim();
            row.Oid = (row.Oid ?? "").Trim();
            row.Unit = string.IsNullOrWhiteSpace(row.Unit) ? null : row.Unit.Trim();
            if (row.Name.Length is < 1 or > 80)
            {
                errors.Add($"Custom OID '{row.Oid}' needs a name.");
            }

            if (!IsOid(row.Oid))
            {
                errors.Add($"'{row.Oid}' is not a numeric OID.");
            }
            else if (!seen.Add(row.Oid))
            {
                errors.Add($"OID {row.Oid} is listed more than once.");
            }
        }

        if (errors.Count > 0)
        {
            return new DeviceSaveResult { Errors = errors };
        }

        var now = DateTime.UtcNow;
        var device = existing ?? new Device { CreatedAt = now };
        device.Name = input.Name;
        device.Host = input.Host;
        device.V3Context = input.V3Context ?? "";
        device.Enabled = input.Enabled;
        if (written is null)
        {
            device.Port = input.Port;
            device.Version = input.Version;
            device.Community = input.Community ?? "public";
            device.V3User = input.V3User ?? "";
            device.V3AuthProtocol = input.V3AuthProtocol;
            device.V3AuthPassword = input.V3AuthPassword ?? "";
            device.V3PrivProtocol = input.V3PrivProtocol;
            device.V3PrivPassword = input.V3PrivPassword ?? "";
            device.PollIntervalSeconds = input.PollIntervalSeconds;
        }
        else
        {
            PolicyStore.WriteDevice(device, written);
        }
        device.GroupName = (input.GroupName ?? "").Trim();
        device.Location = (input.Location ?? "").Trim();
        device.Tags = CsvDevices.NormalizeTags(input.Tags ?? "");
        device.ParentDeviceId = input.ParentDeviceId;
        device.UpdatedAt = now;
        device.NextPollAt = now;

        if (existing is null)
        {
            _db.Devices.Add(device);
        }

        var keep = oids.Where(row => row.Id > 0).Select(row => row.Id).ToHashSet();
        foreach (var old in device.CustomOids.ToList())
        {
            if (!keep.Contains(old.Id))
            {
                _db.CustomOids.Remove(old);
            }
        }

        foreach (var row in oids)
        {
            var match = row.Id > 0 ? device.CustomOids.FirstOrDefault(item => item.Id == row.Id) : null;
            if (match is null)
            {
                device.CustomOids.Add(new CustomOid
                {
                    Name = row.Name,
                    Oid = row.Oid,
                    Unit = row.Unit
                });
            }
            else
            {
                match.Name = row.Name;
                match.Oid = row.Oid;
                match.Unit = row.Unit;
            }
        }

        await PolicyStore.EnsureLocationAsync(_db, device.Location, cancellationToken);
        await _db.SaveChangesAsync(cancellationToken);
        if (written is not null)
        {
            var states = await _db.InterfaceStates.Where(state => state.DeviceId == device.Id).ToListAsync(cancellationToken);
            var catalog = await PolicyStore.LoadAsync(_db, cancellationToken);
            InterfaceMonitorService.Apply(catalog.Resolve(device).InterfaceRules(), states);
            await _db.SaveChangesAsync(cancellationToken);
        }

        return new DeviceSaveResult { Device = device };
    }

    public async Task<bool> DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
        if (device is null)
        {
            return false;
        }

        await _db.CustomOidSamples.Where(s => s.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.InterfaceSamples.Where(s => s.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.DeviceSamples.Where(s => s.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.InterfaceStates.Where(s => s.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.Alerts.Where(a => a.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.Rules.Where(r => r.DeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.Links.Where(link => link.SourceDeviceId == id || link.TargetDeviceId == id).ExecuteDeleteAsync(cancellationToken);
        await _db.Devices.Where(device => device.ParentDeviceId == id).ExecuteUpdateAsync(setters => setters.SetProperty(device => device.ParentDeviceId, (int?)null), cancellationToken);
        _db.Devices.Remove(device);
        await _db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public static bool IsOid(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 200 || text.StartsWith('.') || text.EndsWith('.'))
        {
            return false;
        }

        var parts = text.Split('.');
        if (parts.Length < 2 || parts[0] is not ("0" or "1" or "2"))
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 10 || !part.All(char.IsDigit))
            {
                return false;
            }
        }

        return true;
    }

    private static string Normalize(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private async Task<bool> ParentCycleAsync(int deviceId, int parentId, CancellationToken cancellationToken)
    {
        var parents = await _db.Devices.AsNoTracking()
            .Select(device => new { device.Id, device.ParentDeviceId })
            .ToDictionaryAsync(device => device.Id, device => device.ParentDeviceId, cancellationToken);
        var cursor = parentId;
        var guard = 0;
        while (parents.TryGetValue(cursor, out var next) && guard++ < parents.Count + 1)
        {
            if (cursor == deviceId)
            {
                return true;
            }

            if (next is not int parent)
            {
                return false;
            }

            cursor = parent;
        }

        return cursor == deviceId;
    }
}
