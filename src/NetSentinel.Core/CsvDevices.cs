using System.Globalization;
using System.Text;

namespace NetSentinel.Core;

public enum CsvRowStatus
{
    Ready,
    Duplicate,
    Error
}

public sealed record ExistingDeviceRef(int Id, string Name, string Host, int Port, int? ParentDeviceId);

public sealed record CsvDeviceRow(
    int Line,
    string Name,
    string Host,
    string Version,
    string Community,
    string V3User,
    string V3AuthProtocol,
    string V3AuthPassword,
    string V3PrivProtocol,
    string V3PrivPassword,
    string PollInterval,
    string Port,
    string Group,
    string Location,
    string Tags,
    string Parent);

public sealed record CsvPreviewRow(
    int Line,
    string Name,
    string Host,
    string Version,
    string Port,
    string Group,
    string Location,
    string Tags,
    string Parent,
    CsvRowStatus Status,
    int? ExistingDeviceId,
    string? DuplicateMatch,
    IReadOnlyList<string> Errors);

public sealed record CsvPreview(
    string? FileError,
    IReadOnlyList<CsvPreviewRow> Rows)
{
    public int Ready => Rows.Count(row => row.Status == CsvRowStatus.Ready);
    public int Duplicates => Rows.Count(row => row.Status == CsvRowStatus.Duplicate);
    public int Errors => Rows.Count(row => row.Status == CsvRowStatus.Error);
}

public static class CsvDevices
{
    public const int MaxRows = 1000;
    public const int MaxCharacters = 512 * 1024;

    public const string Template =
        "name,host,version,community,v3_user,v3_auth_protocol,v3_auth_password,v3_priv_protocol,v3_priv_password,poll_interval,port,group,location,tags,parent\r\n" +
        "Core switch,10.0.0.1,v2c,public,,,,,60,161,campus,MDF,\"core,edge\",\r\n" +
        "Access switch,10.0.0.2,v2c,public,,,,,120,161,campus,IDF,access,Core switch\r\n" +
        "Border router,10.0.0.3,v3,,monitor,SHA256,auth-pass,AES,priv-pass,60,161,edge,MPOE,wan,\r\n";

    private static readonly string[] HeaderOrder =
    {
        "name", "host", "version", "community", "v3_user", "v3_auth_protocol", "v3_auth_password",
        "v3_priv_protocol", "v3_priv_password", "poll_interval", "port", "group", "location", "tags", "parent"
    };

    private static readonly Dictionary<string, string> HeaderAliases = BuildAliases();

    public static CsvPreview Preview(string? csv, IReadOnlyList<ExistingDeviceRef> existing)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            return new CsvPreview("The file is empty.", Array.Empty<CsvPreviewRow>());
        }

        if (csv.Length > MaxCharacters)
        {
            return new CsvPreview($"The file is larger than {MaxCharacters / 1024} KB.", Array.Empty<CsvPreviewRow>());
        }

        List<CsvDeviceRow> parsed;
        try
        {
            parsed = Parse(csv);
        }
        catch (InvalidDataException ex)
        {
            return new CsvPreview(ex.Message, Array.Empty<CsvPreviewRow>());
        }

        if (parsed.Count == 0)
        {
            return new CsvPreview("The file has a header but no device rows.", Array.Empty<CsvPreviewRow>());
        }

        if (parsed.Count > MaxRows)
        {
            return new CsvPreview($"A file can contain at most {MaxRows} devices. This one has {parsed.Count}.", Array.Empty<CsvPreviewRow>());
        }

        return new CsvPreview(null, Validate(parsed, existing));
    }

    public static string Export(IEnumerable<CsvDeviceRow> rows)
    {
        var builder = new StringBuilder();
        builder.Append(string.Join(',', HeaderOrder));
        builder.Append("\r\n");
        foreach (var row in rows)
        {
            var cells = new[]
            {
                row.Name, row.Host, row.Version, row.Community, row.V3User, row.V3AuthProtocol, row.V3AuthPassword,
                row.V3PrivProtocol, row.V3PrivPassword, row.PollInterval, row.Port, row.Group, row.Location, row.Tags, row.Parent
            };
            builder.Append(string.Join(',', cells.Select(Escape)));
            builder.Append("\r\n");
        }

        return builder.ToString();
    }

    public static List<CsvDeviceRow> Parse(string csv)
    {
        var text = csv.TrimStart('\uFEFF');
        var records = ReadRecords(text);
        if (records.Count == 0 || records[0].Cells.All(string.IsNullOrWhiteSpace))
        {
            throw new InvalidDataException("The file needs a header row.");
        }

        var header = records[0];
        var columns = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < header.Cells.Count; i++)
        {
            var canonical = CanonicalHeader(header.Cells[i]);
            if (canonical is null)
            {
                continue;
            }

            if (columns.ContainsKey(canonical))
            {
                throw new InvalidDataException($"The header '{header.Cells[i].Trim()}' is repeated.");
            }

            columns[canonical] = i;
        }

        if (!columns.ContainsKey("name") || !columns.ContainsKey("host"))
        {
            throw new InvalidDataException("The header must include name and host (or ip).");
        }

        var rows = new List<CsvDeviceRow>();
        foreach (var record in records.Skip(1))
        {
            if (record.Cells.All(string.IsNullOrWhiteSpace))
            {
                continue;
            }

            string Cell(string key) => columns.TryGetValue(key, out var index) && index < record.Cells.Count
                ? record.Cells[index].Trim()
                : "";

            rows.Add(new CsvDeviceRow(
                record.Line,
                Cell("name"),
                Cell("host"),
                Cell("version"),
                Cell("community"),
                Cell("v3_user"),
                Cell("v3_auth_protocol"),
                Cell("v3_auth_password"),
                Cell("v3_priv_protocol"),
                Cell("v3_priv_password"),
                Cell("poll_interval"),
                Cell("port"),
                Cell("group"),
                Cell("location"),
                Cell("tags"),
                Cell("parent")));
        }

        return rows;
    }

    private static List<CsvPreviewRow> Validate(IReadOnlyList<CsvDeviceRow> rows, IReadOnlyList<ExistingDeviceRef> existing)
    {
        var previews = new List<(CsvDeviceRow Row, List<string> Errors, int? ExistingId, string? Match)>();
        var seenNames = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var seenHosts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows)
        {
            var errors = new List<string>();
            if (row.Name.Length is < 1 or > 80)
            {
                errors.Add("Name must be 1–80 characters.");
            }

            if (row.Host.Length is < 1 or > 255)
            {
                errors.Add("Host must be a hostname or IP address.");
            }

            if (!string.IsNullOrEmpty(row.Name) && seenNames.TryGetValue(row.Name, out var nameLine))
            {
                errors.Add($"Name is also used on line {nameLine}.");
            }
            else if (!string.IsNullOrEmpty(row.Name))
            {
                seenNames[row.Name] = row.Line;
            }

            var port = 161;
            if (!string.IsNullOrEmpty(row.Port) && (!int.TryParse(row.Port, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535))
            {
                errors.Add("Port must be between 1 and 65535.");
                port = 0;
            }

            if (port > 0 && !string.IsNullOrEmpty(row.Host))
            {
                var hostKey = HostKey(row.Host, port);
                if (seenHosts.TryGetValue(hostKey, out var hostLine))
                {
                    errors.Add($"Host and port are also used on line {hostLine}.");
                }
                else
                {
                    seenHosts[hostKey] = row.Line;
                }
            }

            if (!string.IsNullOrEmpty(row.PollInterval)
                && (!int.TryParse(row.PollInterval, NumberStyles.None, CultureInfo.InvariantCulture, out var interval) || interval is < 5 or > 86400))
            {
                errors.Add("Poll interval must be between 5 and 86400 seconds.");
            }

            if (!TryParseVersion(row.Version, out var version))
            {
                errors.Add("Version must be v1, v2c, or v3.");
                version = SnmpVersion.V2C;
            }

            ValidateSecrets(row, version, errors);
            if (row.Group.Length > 80) errors.Add("Group must be 80 characters or fewer.");
            if (row.Location.Length > 80) errors.Add("Location must be 80 characters or fewer.");
            if (row.Tags.Length > 200) errors.Add("Tags must be 200 characters or fewer.");

            int? existingId = null;
            string? match = null;
            if (errors.Count == 0)
            {
                var byName = existing.Where(device => string.Equals(device.Name, row.Name, StringComparison.OrdinalIgnoreCase)).ToList();
                var byHost = existing.Where(device => HostEquals(device.Host, row.Host) && device.Port == port).ToList();
                if (byName.Count > 1 || byHost.Count > 1)
                {
                    errors.Add("More than one existing device matches this row.");
                }
                else if (byName.Count == 1 && byHost.Count == 1 && byName[0].Id != byHost[0].Id)
                {
                    errors.Add("The name and the host match two different devices.");
                }
                else if (byHost.Count == 1)
                {
                    existingId = byHost[0].Id;
                    match = "host";
                }
                else if (byName.Count == 1)
                {
                    existingId = byName[0].Id;
                    match = "name";
                }
            }

            previews.Add((row, errors, existingId, match));
        }

        var namesInFile = previews
            .Where(item => item.Errors.Count == 0)
            .Select(item => item.Row.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var hostsInFile = previews
            .Where(item => item.Errors.Count == 0 && !string.IsNullOrEmpty(item.Row.Host))
            .Select(item => item.Row.Host)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var item in previews)
        {
            if (string.IsNullOrWhiteSpace(item.Row.Parent))
            {
                continue;
            }

            var parent = item.Row.Parent.Trim();
            if (string.Equals(parent, item.Row.Name, StringComparison.OrdinalIgnoreCase)
                || HostEquals(parent, item.Row.Host))
            {
                item.Errors.Add("A device cannot be its own parent.");
                continue;
            }

            var known = namesInFile.Contains(parent)
                || hostsInFile.Contains(parent)
                || existing.Any(device => string.Equals(device.Name, parent, StringComparison.OrdinalIgnoreCase) || HostEquals(device.Host, parent));
            if (!known)
            {
                item.Errors.Add($"Parent '{parent}' is not in this file or the device list.");
            }
        }

        string? Canonical(string token)
        {
            var row = previews.FirstOrDefault(item => item.Errors.Count == 0 && (string.Equals(item.Row.Name, token, StringComparison.OrdinalIgnoreCase) || HostEquals(item.Row.Host, token)));
            if (row.Row is not null)
            {
                return row.Row.Name;
            }

            var device = existing.FirstOrDefault(item => string.Equals(item.Name, token, StringComparison.OrdinalIgnoreCase) || HostEquals(item.Host, token));
            return device?.Name;
        }

        var parentOf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var device in existing)
        {
            if (device.ParentDeviceId is int parentId)
            {
                var parent = existing.FirstOrDefault(item => item.Id == parentId);
                if (parent is not null)
                {
                    parentOf[device.Name] = parent.Name;
                }
            }
        }

        foreach (var item in previews.Where(item => item.Errors.Count == 0 && !string.IsNullOrWhiteSpace(item.Row.Parent)))
        {
            var canonical = Canonical(item.Row.Parent.Trim());
            if (!string.IsNullOrEmpty(canonical))
            {
                parentOf[item.Row.Name] = canonical;
            }
        }

        var cyclic = FindCyclicNames(parentOf);
        if (cyclic.Count > 0)
        {
            foreach (var item in previews)
            {
                if (cyclic.Contains(item.Row.Name) && !string.IsNullOrWhiteSpace(item.Row.Parent))
                {
                    item.Errors.Add("This parent link is part of a cycle.");
                }
            }
        }

        return previews.Select(item => new CsvPreviewRow(
            item.Row.Line,
            item.Row.Name,
            item.Row.Host,
            string.IsNullOrWhiteSpace(item.Row.Version) ? "v2c" : item.Row.Version,
            string.IsNullOrWhiteSpace(item.Row.Port) ? "161" : item.Row.Port,
            item.Row.Group,
            item.Row.Location,
            item.Row.Tags,
            item.Row.Parent,
            item.Errors.Count > 0 ? CsvRowStatus.Error : item.ExistingId is null ? CsvRowStatus.Ready : CsvRowStatus.Duplicate,
            item.Errors.Count > 0 ? null : item.ExistingId,
            item.Errors.Count > 0 ? null : item.Match,
            item.Errors)).ToList();
    }

    public static bool TryParseVersion(string? text, out SnmpVersion version)
    {
        var value = (text ?? "").Trim().ToLowerInvariant().Replace(" ", "", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal);
        switch (value)
        {
            case "":
            case "v2":
            case "v2c":
            case "2":
            case "2c":
            case "snmpv2":
            case "snmpv2c":
                version = SnmpVersion.V2C;
                return true;
            case "v1":
            case "1":
            case "snmpv1":
                version = SnmpVersion.V1;
                return true;
            case "v3":
            case "3":
            case "snmpv3":
                version = SnmpVersion.V3;
                return true;
            default:
                version = SnmpVersion.V2C;
                return false;
        }
    }

    public static string NormalizeTags(string tags)
    {
        var parts = tags.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        return string.Join(", ", parts);
    }

    private static void ValidateSecrets(CsvDeviceRow row, SnmpVersion version, List<string> errors)
    {
        if (version is SnmpVersion.V1 or SnmpVersion.V2C)
        {
            if (string.IsNullOrWhiteSpace(row.Community) || row.Community.Length > 128)
            {
                errors.Add("A community string is required for SNMP v1 and v2c.");
            }

            return;
        }

        var auth = string.IsNullOrWhiteSpace(row.V3AuthProtocol) ? "None" : row.V3AuthProtocol.Trim();
        var priv = string.IsNullOrWhiteSpace(row.V3PrivProtocol) ? "None" : row.V3PrivProtocol.Trim();
        if (string.IsNullOrWhiteSpace(row.V3User) || row.V3User.Length > 64)
        {
            errors.Add("An SNMPv3 user name is required.");
        }

        if (!IsAuth(auth)) errors.Add($"Authentication protocol '{auth}' is not supported.");
        if (!IsPriv(priv)) errors.Add($"Privacy protocol '{priv}' is not supported.");
        if (!auth.Equals("None", StringComparison.OrdinalIgnoreCase) && row.V3AuthPassword.Length < 8)
        {
            errors.Add("SNMPv3 authentication passwords must be at least 8 characters.");
        }

        if (!priv.Equals("None", StringComparison.OrdinalIgnoreCase))
        {
            if (auth.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add("Privacy requires authentication.");
            }

            if (row.V3PrivPassword.Length < 8)
            {
                errors.Add("SNMPv3 privacy passwords must be at least 8 characters.");
            }
        }
    }

    private static bool IsAuth(string value) => value.ToUpperInvariant() is "NONE" or "MD5" or "SHA1" or "SHA" or "SHA256" or "SHA384" or "SHA512";

    private static bool IsPriv(string value) => value.ToUpperInvariant() is "NONE" or "DES" or "AES" or "AES128" or "AES192" or "AES256";

    private static HashSet<string> FindCyclicNames(Dictionary<string, string> parentOf)
    {
        var cyclic = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var start in parentOf.Keys.ToList())
        {
            var seen = new List<string>();
            var cursor = start;
            var guard = 0;
            while (parentOf.TryGetValue(cursor, out var parent) && guard++ < parentOf.Count + 2)
            {
                var again = seen.FindIndex(item => string.Equals(item, cursor, StringComparison.OrdinalIgnoreCase));
                if (again >= 0)
                {
                    foreach (var name in seen.Skip(again))
                    {
                        cyclic.Add(name);
                    }

                    break;
                }

                seen.Add(cursor);
                cursor = parent;
            }
        }

        return cyclic;
    }

    private static string HostKey(string host, int port) => host.Trim().TrimEnd('.').ToLowerInvariant() + ":" + port.ToString(CultureInfo.InvariantCulture);

    private static bool HostEquals(string left, string right)
        => string.Equals(left.Trim().TrimEnd('.'), right.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase);

    private static string? CanonicalHeader(string header)
    {
        var key = header.Trim().TrimStart('\uFEFF').ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
        while (key.Contains("__", StringComparison.Ordinal))
        {
            key = key.Replace("__", "_", StringComparison.Ordinal);
        }

        return HeaderAliases.TryGetValue(key, out var canonical) ? canonical : null;
    }

    private static Dictionary<string, string> BuildAliases()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Add(string canonical, params string[] aliases)
        {
            map[canonical] = canonical;
            foreach (var alias in aliases)
            {
                map[alias] = canonical;
            }
        }

        Add("name", "device", "device_name", "sysname");
        Add("host", "ip", "hostname", "address", "host_ip", "ip_address");
        Add("version", "snmp_version", "snmpversion");
        Add("community", "snmp_community");
        Add("v3_user", "v3user", "user", "username", "security_name");
        Add("v3_auth_protocol", "auth_protocol", "authprotocol", "v3_auth");
        Add("v3_auth_password", "auth_password", "auth_pass", "v3_auth_pass");
        Add("v3_priv_protocol", "priv_protocol", "privprotocol", "v3_priv");
        Add("v3_priv_password", "priv_password", "priv_pass", "v3_priv_pass");
        Add("poll_interval", "interval", "poll_interval_seconds", "pollinterval");
        Add("port", "snmp_port");
        Add("group", "group_name");
        Add("location", "site");
        Add("tags", "tag", "labels");
        Add("parent", "uplink", "parent_device", "uplink_device");
        return map;
    }

    private static string Escape(string value)
    {
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
        {
            return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        }

        return value;
    }

    private static List<CsvRecord> ReadRecords(string text)
    {
        var records = new List<CsvRecord>();
        var cells = new List<string>();
        var cell = new StringBuilder();
        var inQuotes = false;
        var line = 1;
        var recordLine = 1;
        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"')
                    {
                        cell.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    if (ch == '\n')
                    {
                        line++;
                    }

                    cell.Append(ch);
                }

                continue;
            }

            if (ch == '"')
            {
                inQuotes = true;
                continue;
            }

            if (ch == ',')
            {
                cells.Add(cell.ToString());
                cell.Clear();
                continue;
            }

            if (ch == '\r')
            {
                continue;
            }

            if (ch == '\n')
            {
                cells.Add(cell.ToString());
                cell.Clear();
                records.Add(new CsvRecord(recordLine, cells));
                cells = new List<string>();
                line++;
                recordLine = line;
                continue;
            }

            cell.Append(ch);
        }

        if (inQuotes)
        {
            throw new InvalidDataException($"A quoted value starting on line {recordLine} is not closed.");
        }

        if (cell.Length > 0 || cells.Count > 0)
        {
            cells.Add(cell.ToString());
            records.Add(new CsvRecord(recordLine, cells));
        }

        return records;
    }

    private sealed record CsvRecord(int Line, List<string> Cells);
}
