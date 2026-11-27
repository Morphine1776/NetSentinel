using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using NetSentinel.Services;
using System.Data.Common;

namespace NetSentinel.Data;

public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Device> Devices => Set<Device>();
    public DbSet<CustomOid> CustomOids => Set<CustomOid>();
    public DbSet<DeviceSample> DeviceSamples => Set<DeviceSample>();
    public DbSet<InterfaceState> InterfaceStates => Set<InterfaceState>();
    public DbSet<InterfaceSample> InterfaceSamples => Set<InterfaceSample>();
    public DbSet<CustomOidSample> CustomOidSamples => Set<CustomOidSample>();
    public DbSet<TrapEvent> Traps => Set<TrapEvent>();
    public DbSet<AlertEvent> Alerts => Set<AlertEvent>();
    public DbSet<AlertRule> Rules => Set<AlertRule>();
    public DbSet<AppSetting> Settings => Set<AppSetting>();
    public DbSet<DeviceLink> Links => Set<DeviceLink>();
    public DbSet<MonitorPolicy> Policies => Set<MonitorPolicy>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Device>(entity =>
        {
            entity.Property(d => d.Name).HasMaxLength(80);
            entity.Property(d => d.Host).HasMaxLength(255);
            entity.Property(d => d.GroupName).HasMaxLength(80);
            entity.Property(d => d.Location).HasMaxLength(80);
            entity.Property(d => d.Tags).HasMaxLength(200);
            entity.Property(d => d.IfIncludePattern).HasMaxLength(500);
            entity.Property(d => d.IfExcludePattern).HasMaxLength(500);
            entity.Property(d => d.IfPatternSyntax).HasMaxLength(16);
            entity.Property(d => d.IfMatchFields).HasMaxLength(40);
            entity.Property(d => d.HaState).HasMaxLength(40);
            entity.Property(d => d.HaPeerState).HasMaxLength(80);
            entity.Property(d => d.HaVendor).HasMaxLength(32);
            entity.HasIndex(d => new { d.Enabled, d.NextPollAt });
            entity.HasMany(d => d.CustomOids)
                .WithOne(o => o.Device)
                .HasForeignKey(o => o.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<CustomOid>(entity =>
        {
            entity.Property(o => o.Name).HasMaxLength(80);
            entity.Property(o => o.Oid).HasMaxLength(200);
            entity.HasIndex(o => o.DeviceId);
        });

        modelBuilder.Entity<DeviceSample>(entity =>
        {
            entity.HasIndex(s => new { s.DeviceId, s.Timestamp });
        });

        modelBuilder.Entity<InterfaceState>(entity =>
        {
            entity.HasKey(s => new { s.DeviceId, s.IfIndex });
            entity.Property(s => s.Monitored).HasDefaultValue(true);
        });

        modelBuilder.Entity<InterfaceSample>(entity =>
        {
            entity.HasIndex(s => new { s.DeviceId, s.IfIndex, s.Timestamp });
        });

        modelBuilder.Entity<CustomOidSample>(entity =>
        {
            entity.HasIndex(s => new { s.CustomOidId, s.Timestamp });
        });

        modelBuilder.Entity<TrapEvent>(entity =>
        {
            entity.HasIndex(t => t.ReceivedAt);
            entity.Property(t => t.Varbinds).HasMaxLength(8000);
        });

        modelBuilder.Entity<AlertEvent>(entity =>
        {
            entity.HasIndex(a => new { a.State, a.CreatedAt });
            entity.HasIndex(a => new { a.DedupKey, a.State });
            entity.Property(a => a.Message).HasMaxLength(1000);
        });

        modelBuilder.Entity<AlertRule>(entity =>
        {
            entity.Property(r => r.Name).HasMaxLength(80);
            entity.Property(r => r.Metric).HasMaxLength(40);
        });

        modelBuilder.Entity<MonitorPolicy>(entity =>
        {
            entity.ToTable("MonitorPolicies");
            entity.Property(policy => policy.Scope).HasMaxLength(16);
            entity.Property(policy => policy.LocationKey).HasMaxLength(80);
            entity.Property(policy => policy.DisplayName).HasMaxLength(80);
            entity.Property(policy => policy.IfIncludePattern).HasMaxLength(500);
            entity.Property(policy => policy.IfExcludePattern).HasMaxLength(500);
            entity.Property(policy => policy.IfPatternSyntax).HasMaxLength(16);
            entity.Property(policy => policy.IfMatchFields).HasMaxLength(40);
            entity.HasIndex(policy => new { policy.Scope, policy.LocationKey }).IsUnique();
        });

        modelBuilder.Entity<DeviceLink>(entity =>
        {
            entity.ToTable("DeviceLinks");
            entity.Property(link => link.Kind).HasMaxLength(16);
            entity.Property(link => link.LocalPort).HasMaxLength(80);
            entity.Property(link => link.RemotePort).HasMaxLength(80);
            entity.HasIndex(link => new { link.SourceDeviceId, link.Kind });
            entity.HasIndex(link => new { link.SourceDeviceId, link.TargetDeviceId, link.Kind }).IsUnique();
        });
    }
}

public sealed class SqlitePragmaInterceptor : DbConnectionInterceptor
{
    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";
        command.ExecuteNonQuery();
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}

public static class SchemaUpgrader
{
    public static async Task ApplyAsync(AppDbContext db, CancellationToken cancellationToken = default)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken);
        }

        var columns = await ReadColumnNames(connection, "Devices", cancellationToken);
        if (columns.Count == 0)
        {
            return;
        }

        await AddColumn(connection, columns, "GroupName", "ALTER TABLE Devices ADD COLUMN GroupName TEXT NOT NULL DEFAULT ''", cancellationToken);
        await AddColumn(connection, columns, "Location", "ALTER TABLE Devices ADD COLUMN Location TEXT NOT NULL DEFAULT ''", cancellationToken);
        await AddColumn(connection, columns, "Tags", "ALTER TABLE Devices ADD COLUMN Tags TEXT NOT NULL DEFAULT ''", cancellationToken);
        await AddColumn(connection, columns, "ParentDeviceId", "ALTER TABLE Devices ADD COLUMN ParentDeviceId INTEGER NULL", cancellationToken);
        await AddColumn(connection, columns, "MapX", "ALTER TABLE Devices ADD COLUMN MapX REAL NULL", cancellationToken);
        await AddColumn(connection, columns, "MapY", "ALTER TABLE Devices ADD COLUMN MapY REAL NULL", cancellationToken);
        await AddColumn(connection, columns, "IfIncludePattern", "ALTER TABLE Devices ADD COLUMN IfIncludePattern TEXT NOT NULL DEFAULT ''", cancellationToken);
        await AddColumn(connection, columns, "IfExcludePattern", "ALTER TABLE Devices ADD COLUMN IfExcludePattern TEXT NOT NULL DEFAULT ''", cancellationToken);
        await AddColumn(connection, columns, "IfPatternSyntax", "ALTER TABLE Devices ADD COLUMN IfPatternSyntax TEXT NOT NULL DEFAULT 'glob'", cancellationToken);
        await AddColumn(connection, columns, "IfMatchFields", "ALTER TABLE Devices ADD COLUMN IfMatchFields TEXT NOT NULL DEFAULT 'name,descr,alias'", cancellationToken);
        await AddColumn(connection, columns, "IfExcludeAdminDown", "ALTER TABLE Devices ADD COLUMN IfExcludeAdminDown INTEGER NOT NULL DEFAULT 0", cancellationToken);
        await AddColumn(connection, columns, "IfRequireAlias", "ALTER TABLE Devices ADD COLUMN IfRequireAlias INTEGER NOT NULL DEFAULT 0", cancellationToken);
        await AddColumn(connection, columns, "TimeoutMs", "ALTER TABLE Devices ADD COLUMN TimeoutMs INTEGER NULL", cancellationToken);
        await AddColumn(connection, columns, "Retries", "ALTER TABLE Devices ADD COLUMN Retries INTEGER NULL", cancellationToken);
        await AddColumn(connection, columns, "UnmonitorDown", "ALTER TABLE Devices ADD COLUMN UnmonitorDown INTEGER NULL", cancellationToken);
        await AddColumn(connection, columns, "AlertOnHaChange", "ALTER TABLE Devices ADD COLUMN AlertOnHaChange INTEGER NULL", cancellationToken);
        await AddColumn(connection, columns, "HaState", "ALTER TABLE Devices ADD COLUMN HaState TEXT NULL", cancellationToken);
        await AddColumn(connection, columns, "HaPeerState", "ALTER TABLE Devices ADD COLUMN HaPeerState TEXT NULL", cancellationToken);
        await AddColumn(connection, columns, "HaVendor", "ALTER TABLE Devices ADD COLUMN HaVendor TEXT NULL", cancellationToken);
        await AddColumn(connection, columns, "HaCheckedAt", "ALTER TABLE Devices ADD COLUMN HaCheckedAt TEXT NULL", cancellationToken);
        await RelaxPolicyColumnsAsync(connection, cancellationToken);

        var interfaceColumns = await ReadColumnNames(connection, "InterfaceStates", cancellationToken);
        if (interfaceColumns.Count > 0)
        {
            await AddColumn(connection, interfaceColumns, "Monitored", "ALTER TABLE InterfaceStates ADD COLUMN Monitored INTEGER NOT NULL DEFAULT 1", cancellationToken);
            await AddColumn(connection, interfaceColumns, "MonitorOverride", "ALTER TABLE InterfaceStates ADD COLUMN MonitorOverride INTEGER NULL", cancellationToken);
        }

        foreach (var sql in new[]
        {
            """
            CREATE TABLE IF NOT EXISTS DeviceLinks (
                Id INTEGER NOT NULL CONSTRAINT PK_DeviceLinks PRIMARY KEY AUTOINCREMENT,
                SourceDeviceId INTEGER NOT NULL,
                TargetDeviceId INTEGER NOT NULL,
                Kind TEXT NOT NULL,
                LocalIfIndex INTEGER NULL,
                LocalPort TEXT NOT NULL DEFAULT '',
                RemotePort TEXT NOT NULL DEFAULT '',
                Utilization REAL NULL,
                UpdatedAt TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS IX_DeviceLinks_SourceDeviceId_Kind ON DeviceLinks (SourceDeviceId, Kind)",
            "CREATE UNIQUE INDEX IF NOT EXISTS IX_DeviceLinks_SourceDeviceId_TargetDeviceId_Kind ON DeviceLinks (SourceDeviceId, TargetDeviceId, Kind)",
            """
            CREATE TABLE IF NOT EXISTS MonitorPolicies (
                Id INTEGER NOT NULL CONSTRAINT PK_MonitorPolicies PRIMARY KEY AUTOINCREMENT,
                Scope TEXT NOT NULL,
                LocationKey TEXT NOT NULL DEFAULT '',
                DisplayName TEXT NOT NULL DEFAULT '',
                SnmpVersion INTEGER NULL,
                Community TEXT NULL,
                V3User TEXT NULL,
                V3AuthProtocol TEXT NULL,
                V3AuthSecret TEXT NULL,
                V3PrivProtocol TEXT NULL,
                V3PrivSecret TEXT NULL,
                Port INTEGER NULL,
                PollIntervalSeconds INTEGER NULL,
                TimeoutMs INTEGER NULL,
                Retries INTEGER NULL,
                IfIncludePattern TEXT NULL,
                IfExcludePattern TEXT NULL,
                IfPatternSyntax TEXT NULL,
                IfMatchFields TEXT NULL,
                IfExcludeAdminDown INTEGER NULL,
                IfRequireAlias INTEGER NULL,
                UnmonitorDown INTEGER NULL,
                AlertOnHaChange INTEGER NULL
            )
            """,
            "CREATE UNIQUE INDEX IF NOT EXISTS IX_MonitorPolicies_Scope_LocationKey ON MonitorPolicies (Scope, LocationKey)"
        })
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task<HashSet<string>> ReadColumnNames(System.Data.Common.DbConnection connection, string table, CancellationToken cancellationToken)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}')";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            names.Add(reader.GetString(0));
        }

        return names;
    }

    private static readonly string[] RelaxedDeviceColumns =
    {
        "Port", "Version", "Community", "V3User", "V3AuthProtocol", "V3AuthPassword", "V3PrivProtocol", "V3PrivPassword",
        "PollIntervalSeconds", "IfIncludePattern", "IfExcludePattern", "IfPatternSyntax", "IfMatchFields",
        "IfExcludeAdminDown", "IfRequireAlias"
    };

    private sealed record SqliteColumn(string Name, string Type, bool NotNull, string? DefaultSql, int PrimaryKey);

    private static async Task RelaxPolicyColumnsAsync(System.Data.Common.DbConnection connection, CancellationToken cancellationToken)
    {
        var columns = await ReadColumnDetails(connection, "Devices", cancellationToken);
        var port = columns.FirstOrDefault(column => column.Name.Equals("Port", StringComparison.OrdinalIgnoreCase));
        if (port is null || !port.NotNull)
        {
            return;
        }

        var relax = new HashSet<string>(RelaxedDeviceColumns, StringComparer.OrdinalIgnoreCase);
        var definitions = new List<string>();
        var names = new List<string>();
        foreach (var column in columns)
        {
            names.Add(Quote(column.Name));
            if (column.PrimaryKey == 1 && column.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
            {
                definitions.Add($"{Quote(column.Name)} INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT");
                continue;
            }

            var type = string.IsNullOrWhiteSpace(column.Type) ? "TEXT" : column.Type;
            if (relax.Contains(column.Name))
            {
                definitions.Add($"{Quote(column.Name)} {type} NULL");
                continue;
            }

            var notNull = column.NotNull ? " NOT NULL" : " NULL";
            var fallback = column.DefaultSql;
            definitions.Add($"{Quote(column.Name)} {type}{notNull}{(fallback is null ? "" : " DEFAULT " + fallback)}");
        }

        var insertList = string.Join(", ", names);
        var create = $"CREATE TABLE \"Devices__policy\" ({string.Join(", ", definitions)})";
        await ExecuteAsync(connection, "PRAGMA foreign_keys=OFF", cancellationToken);
        try
        {
            await ExecuteAsync(connection, create, cancellationToken);
            await ExecuteAsync(connection, $"INSERT INTO \"Devices__policy\" ({insertList}) SELECT {insertList} FROM \"Devices\"", cancellationToken);
            await ExecuteAsync(connection, "DROP TABLE \"Devices\"", cancellationToken);
            await ExecuteAsync(connection, "ALTER TABLE \"Devices__policy\" RENAME TO \"Devices\"", cancellationToken);
            await ExecuteAsync(connection, "CREATE INDEX IF NOT EXISTS \"IX_Devices_Enabled_NextPollAt\" ON \"Devices\" (\"Enabled\", \"NextPollAt\")", cancellationToken);
        }
        finally
        {
            await ExecuteAsync(connection, "PRAGMA foreign_keys=ON", cancellationToken);
        }
    }

    private static async Task<List<SqliteColumn>> ReadColumnDetails(System.Data.Common.DbConnection connection, string table, CancellationToken cancellationToken)
    {
        var columns = new List<SqliteColumn>();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('{table}')";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            columns.Add(new SqliteColumn(
                reader.GetString(0),
                reader.IsDBNull(1) ? "" : reader.GetString(1),
                !reader.IsDBNull(2) && reader.GetInt64(2) == 1,
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? 0 : (int)reader.GetInt64(4)));
        }

        return columns;
    }

    private static async Task ExecuteAsync(System.Data.Common.DbConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string Quote(string name) => "\"" + name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static async Task AddColumn(System.Data.Common.DbConnection connection, HashSet<string> columns, string name, string sql, CancellationToken cancellationToken)
    {
        if (columns.Contains(name))
        {
            return;
        }

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
        columns.Add(name);
    }
}

public static class DbInitializer
{
    public static async Task SeedAsync(AppDbContext db, IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        await SchemaUpgrader.ApplyAsync(db, cancellationToken);
        if (!await db.Settings.AnyAsync(cancellationToken))
        {
            db.Settings.Add(new AppSetting
            {
                RetentionDays = Math.Clamp(configuration.GetValue("Retention:Days", 30), 1, 3650),
                FailureThreshold = Math.Clamp(configuration.GetValue("Snmp:FailureThreshold", 2), 1, 20),
                TrapEnabled = configuration.GetValue("Snmp:TrapEnabled", true),
                TrapPort = Math.Clamp(configuration.GetValue("Snmp:TrapPort", 1162), 1, 65535)
            });
        }

        await PolicyStore.EnsureSeedAsync(db, configuration, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }
}

public static class CounterStorage
{
    public static long Pack(ulong value) => unchecked((long)value);

    public static ulong Unpack(long value) => unchecked((ulong)value);
}
