namespace NetSentinel.Core;

public enum DevicePresence
{
    Reporting,
    Down,
    Pending,
    Paused
}

public enum LocationHealth
{
    Healthy,
    Degraded,
    Critical,
    Waiting
}

public sealed record LocationDeviceInput(
    int Id,
    string Name,
    string Host,
    string? Location,
    DevicePresence Presence,
    bool OpenCriticalAlert);

public sealed record LocationGroup(
    string Key,
    string Name,
    LocationHealth Health,
    string Cue,
    int Total,
    int Reporting,
    int Down,
    int Pending,
    int Paused,
    bool OpenCritical,
    IReadOnlyList<int> DeviceIds);

public static class LocationGroups
{
    public const string UnassignedName = "Unassigned";

    public static DevicePresence Presence(bool enabled, bool polled, bool snmpOk)
    {
        if (!enabled)
        {
            return DevicePresence.Paused;
        }

        if (!polled)
        {
            return DevicePresence.Pending;
        }

        return snmpOk ? DevicePresence.Reporting : DevicePresence.Down;
    }

    public static LocationHealth HealthOf(int total, int reporting, int down, bool openCritical)
    {
        if (openCritical || (total > 0 && down == total))
        {
            return LocationHealth.Critical;
        }

        if (down > 0)
        {
            return LocationHealth.Degraded;
        }

        if (total > 0 && reporting == total)
        {
            return LocationHealth.Healthy;
        }

        return LocationHealth.Waiting;
    }

    public static string CueFor(LocationHealth health, bool allDown)
    {
        if (health == LocationHealth.Critical)
        {
            return allDown ? "All down" : "Critical alert";
        }

        return health switch
        {
            LocationHealth.Healthy => "All reporting",
            LocationHealth.Degraded => "Some down",
            _ => "Waiting"
        };
    }

    public static IReadOnlyList<LocationGroup> Group(IReadOnlyList<LocationDeviceInput> devices)
    {
        ArgumentNullException.ThrowIfNull(devices);

        var buckets = new Dictionary<string, List<LocationDeviceInput>>(StringComparer.Ordinal);
        foreach (var device in devices)
        {
            var key = KeyFor(device.Location);
            if (!buckets.TryGetValue(key, out var bucket))
            {
                bucket = new List<LocationDeviceInput>();
                buckets.Add(key, bucket);
            }

            bucket.Add(device);
        }

        var groups = new List<LocationGroup>(buckets.Count);
        foreach (var (key, bucket) in buckets)
        {
            var reporting = bucket.Count(device => device.Presence == DevicePresence.Reporting);
            var down = bucket.Count(device => device.Presence == DevicePresence.Down);
            var pending = bucket.Count(device => device.Presence == DevicePresence.Pending);
            var paused = bucket.Count(device => device.Presence == DevicePresence.Paused);
            var openCritical = bucket.Any(device => device.OpenCriticalAlert);
            var health = HealthOf(bucket.Count, reporting, down, openCritical);
            var ordered = bucket
                .OrderBy(device => device.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(device => device.Id)
                .Select(device => device.Id)
                .ToList();

            groups.Add(new LocationGroup(
                key,
                DisplayName(key, bucket),
                health,
                CueFor(health, down == bucket.Count && bucket.Count > 0),
                bucket.Count,
                reporting,
                down,
                pending,
                paused,
                openCritical,
                ordered));
        }

        groups.Sort(Compare);
        return groups;
    }

    public static string KeyFor(string? location)
    {
        var trimmed = (location ?? "").Trim();
        return trimmed.Length == 0 ? "" : trimmed.ToUpperInvariant();
    }

    private static string DisplayName(string key, IReadOnlyList<LocationDeviceInput> devices)
    {
        if (key.Length == 0)
        {
            return UnassignedName;
        }

        return devices
            .Select(device => (device.Location ?? "").Trim())
            .Where(location => location.Length > 0)
            .GroupBy(location => location, StringComparer.Ordinal)
            .Select(group => (Name: group.Key, Count: group.Count()))
            .OrderByDescending(item => item.Count)
            .ThenBy(item => item.Name, StringComparer.Ordinal)
            .First()
            .Name;
    }

    private static int Compare(LocationGroup left, LocationGroup right)
    {
        var rank = Rank(left.Health).CompareTo(Rank(right.Health));
        if (rank != 0)
        {
            return rank;
        }

        return string.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);
    }

    private static int Rank(LocationHealth health) => health switch
    {
        LocationHealth.Critical => 0,
        LocationHealth.Degraded => 1,
        LocationHealth.Waiting => 2,
        _ => 3
    };
}
