using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Device>(entity =>
        {
            entity.Property(d => d.Name).HasMaxLength(80);
            entity.Property(d => d.Host).HasMaxLength(255);
            entity.Property(d => d.GroupName).HasMaxLength(80);
            entity.Property(d => d.Location).HasMaxLength(80);
            entity.Property(d => d.Tags).HasMaxLength(200);
            entity.Property(d => d.IfIncludePattern).HasMaxLength(500).HasDefaultValue("");
            entity.Property(d => d.IfExcludePattern).HasMaxLength(500).HasDefaultValue("");
            entity.Property(d => d.IfPatternSyntax).HasMaxLength(16).HasDefaultValue("glob");
            entity.Property(d => d.IfMatchFields).HasMaxLength(40).HasDefaultValue("name,descr,alias");
            entity.Property(d => d.IfExcludeAdminDown).HasDefaultValue(false);
            entity.Property(d => d.IfRequireAlias).HasDefaultValue(false);
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
            "CREATE UNIQUE INDEX IF NOT EXISTS IX_DeviceLinks_SourceDeviceId_TargetDeviceId_Kind ON DeviceLinks (SourceDeviceId, TargetDeviceId, Kind)"
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
        if (await db.Settings.AnyAsync(cancellationToken))
        {
            return;
        }

        db.Settings.Add(new AppSetting
        {
            RetentionDays = Math.Clamp(configuration.GetValue("Retention:Days", 30), 1, 3650),
            FailureThreshold = Math.Clamp(configuration.GetValue("Snmp:FailureThreshold", 2), 1, 20),
            TrapEnabled = configuration.GetValue("Snmp:TrapEnabled", true),
            TrapPort = Math.Clamp(configuration.GetValue("Snmp:TrapPort", 1162), 1, 65535)
        });
        await db.SaveChangesAsync(cancellationToken);
    }
}

public static class CounterStorage
{
    public static long Pack(ulong value) => unchecked((long)value);

    public static ulong Unpack(long value) => unchecked((ulong)value);
}
