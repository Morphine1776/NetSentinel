namespace NetSentinel.Core;

public sealed record SnmpBinding(string Oid, string Value);

public sealed record NeighborObservation(
    string Protocol,
    string? RemoteName,
    string? RemoteChassis,
    string? RemoteAddress,
    string? RemotePort,
    string? LocalPort,
    int? LocalPortNum);

public sealed record KnownDevice(int Id, string Name, string Host, string? SysName);

public sealed record KnownInterface(int IfIndex, string Descr, string Name, string Alias, double? InUtil, double? OutUtil);

public sealed record MatchedNeighbor(
    int RemoteDeviceId,
    string Protocol,
    int? LocalIfIndex,
    string LocalPort,
    string RemotePort,
    double? Utilization);

public static class NeighborTables
{
    public const string LldpRemEntry = "1.0.8802.1.1.2.1.4.1.1";
    public const string LldpLocPortEntry = "1.0.8802.1.1.2.1.3.7.1";
    public const string CdpCacheEntry = "1.3.6.1.4.1.9.9.23.1.2.1.1";

    public static List<NeighborObservation> Parse(IEnumerable<SnmpBinding> rows)
    {
        var lldp = new Dictionary<string, MutableNeighbor>(StringComparer.Ordinal);
        var localPorts = new Dictionary<int, string>();
        var cdp = new Dictionary<string, MutableNeighbor>(StringComparer.Ordinal);

        foreach (var row in rows)
        {
            if (TrySplit(row.Oid, LldpRemEntry, out var column, out var index))
            {
                var item = Get(lldp, index);
                item.LocalPortNum ??= SecondIndex(index);
                switch (column)
                {
                    case 5:
                        item.Chassis = Clean(row.Value);
                        break;
                    case 7:
                        item.Port = Clean(row.Value);
                        break;
                    case 8 when string.IsNullOrEmpty(item.Port):
                        item.Port = Clean(row.Value);
                        break;
                    case 9:
                        item.Name = Clean(row.Value);
                        break;
                }
            }
            else if (TrySplit(row.Oid, LldpLocPortEntry, out column, out index) && int.TryParse(index, out var portNum))
            {
                var value = Clean(row.Value);
                if (value.Length == 0)
                {
                    continue;
                }

                if (column == 3 || (column == 4 && !localPorts.ContainsKey(portNum)))
                {
                    localPorts[portNum] = value;
                }
            }
            else if (TrySplit(row.Oid, CdpCacheEntry, out column, out index))
            {
                var item = Get(cdp, index);
                item.LocalPortNum ??= FirstIndex(index);
                switch (column)
                {
                    case 4:
                        item.Address = Clean(row.Value);
                        break;
                    case 6:
                        item.Name = Clean(row.Value);
                        break;
                    case 7:
                        item.Port = Clean(row.Value);
                        break;
                }
            }
        }

        var observations = new List<NeighborObservation>();
        foreach (var item in lldp.Values)
        {
            var localPort = item.LocalPortNum is int number && localPorts.TryGetValue(number, out var name) ? name : null;
            Add(observations, "lldp", item, localPort);
        }

        foreach (var item in cdp.Values)
        {
            Add(observations, "cdp", item, null);
        }

        return observations;
    }

    private static void Add(List<NeighborObservation> observations, string protocol, MutableNeighbor item, string? localPort)
    {
        if (string.IsNullOrWhiteSpace(item.Name) && string.IsNullOrWhiteSpace(item.Chassis) && string.IsNullOrWhiteSpace(item.Address))
        {
            return;
        }

        observations.Add(new NeighborObservation(protocol, item.Name, item.Chassis, item.Address, item.Port, localPort, item.LocalPortNum));
    }

    public static bool TrySplit(string oid, string entry, out int column, out string index)
    {
        column = 0;
        index = "";
        var prefix = entry + ".";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var rest = oid[prefix.Length..];
        var dot = rest.IndexOf('.');
        if (dot <= 0 || dot == rest.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(rest[..dot], out column))
        {
            return false;
        }

        index = rest[(dot + 1)..];
        return true;
    }

    private static int? FirstIndex(string index)
    {
        var dot = index.IndexOf('.');
        var token = dot < 0 ? index : index[..dot];
        return int.TryParse(token, out var value) ? value : null;
    }

    private static int? SecondIndex(string index)
    {
        var parts = index.Split('.');
        return parts.Length >= 2 && int.TryParse(parts[1], out var value) ? value : null;
    }

    private static MutableNeighbor Get(Dictionary<string, MutableNeighbor> map, string key)
    {
        if (!map.TryGetValue(key, out var item))
        {
            item = new MutableNeighbor();
            map[key] = item;
        }

        return item;
    }

    private static string Clean(string? value) => (value ?? "").Trim();

    private sealed class MutableNeighbor
    {
        public string? Name { get; set; }
        public string? Chassis { get; set; }
        public string? Address { get; set; }
        public string? Port { get; set; }
        public int? LocalPortNum { get; set; }
    }
}

public static class NeighborMatcher
{
    public static List<MatchedNeighbor> Match(
        int localDeviceId,
        IReadOnlyList<NeighborObservation> neighbors,
        IReadOnlyList<KnownDevice> devices,
        IReadOnlyList<KnownInterface> interfaces)
    {
        var matches = new List<MatchedNeighbor>();
        var seen = new HashSet<int>();
        foreach (var neighbor in neighbors)
        {
            var remote = FindDevice(localDeviceId, neighbor, devices);
            if (remote is null || !seen.Add(remote.Id))
            {
                continue;
            }

            var ifIndex = FindInterface(neighbor, interfaces);
            var iface = ifIndex is int index ? interfaces.FirstOrDefault(item => item.IfIndex == index) : null;
            matches.Add(new MatchedNeighbor(
                remote.Id,
                neighbor.Protocol,
                ifIndex,
                iface is null ? neighbor.LocalPort ?? "" : First(iface.Name, iface.Descr, neighbor.LocalPort),
                neighbor.RemotePort ?? "",
                Utilization(iface)));
        }

        return matches;
    }

    public static KnownDevice? FindDevice(int localDeviceId, NeighborObservation neighbor, IReadOnlyList<KnownDevice> devices)
    {
        var others = devices.Where(device => device.Id != localDeviceId).ToList();
        foreach (var token in IdentityTokens(neighbor))
        {
            var hits = others.Where(device => NameEquals(device.Name, token) || NameEquals(device.SysName, token)).ToList();
            if (hits.Count == 1)
            {
                return hits[0];
            }
        }

        if (!string.IsNullOrWhiteSpace(neighbor.RemoteAddress))
        {
            var hits = others.Where(device => HostEquals(device.Host, neighbor.RemoteAddress)).ToList();
            if (hits.Count == 1)
            {
                return hits[0];
            }
        }

        return null;
    }

    public static int? FindInterface(NeighborObservation neighbor, IReadOnlyList<KnownInterface> interfaces)
    {
        if (!string.IsNullOrWhiteSpace(neighbor.LocalPort))
        {
            var hit = interfaces.FirstOrDefault(item =>
                NameEquals(item.Name, neighbor.LocalPort)
                || NameEquals(item.Descr, neighbor.LocalPort)
                || NameEquals(item.Alias, neighbor.LocalPort));
            if (hit is not null)
            {
                return hit.IfIndex;
            }
        }

        if (neighbor.LocalPortNum is int number)
        {
            var hit = interfaces.FirstOrDefault(item => item.IfIndex == number);
            if (hit is not null)
            {
                return hit.IfIndex;
            }
        }

        return null;
    }

    public static double? Utilization(KnownInterface? iface)
    {
        if (iface is null)
        {
            return null;
        }

        if (iface.InUtil is double inbound && iface.OutUtil is double outbound)
        {
            return Math.Max(inbound, outbound);
        }

        return iface.InUtil ?? iface.OutUtil;
    }

    private static IEnumerable<string> IdentityTokens(NeighborObservation neighbor)
    {
        foreach (var value in new[] { neighbor.RemoteName, neighbor.RemoteChassis })
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var token = value.Trim();
            yield return token;
            var dot = token.IndexOf('.');
            if (dot > 0)
            {
                yield return token[..dot];
            }
        }
    }

    private static string First(string preferred, string fallback, string? extra)
    {
        if (!string.IsNullOrWhiteSpace(preferred)) return preferred;
        if (!string.IsNullOrWhiteSpace(fallback)) return fallback;
        return extra ?? "";
    }

    private static bool NameEquals(string? left, string? right)
        => !string.IsNullOrWhiteSpace(left)
           && !string.IsNullOrWhiteSpace(right)
           && string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool HostEquals(string left, string right)
        => string.Equals(left.Trim().TrimEnd('.'), right.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
}
