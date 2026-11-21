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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Device>(entity =>
        {
            entity.Property(d => d.Name).HasMaxLength(80);
            entity.Property(d => d.Host).HasMaxLength(255);
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

public static class DbInitializer
{
    public static async Task SeedAsync(AppDbContext db, IConfiguration configuration, CancellationToken cancellationToken = default)
    {
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
