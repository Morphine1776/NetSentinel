using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NetSentinel.Data;
using NetSentinel.Services;

namespace NetSentinel.Tests;

public class SchemaUpgradeTests
{
    [Fact]
    public async Task Upgrade_adds_monitor_columns_and_keeps_existing_ports_monitored()
    {
        var path = Path.Combine(Path.GetTempPath(), "netsentinel-upgrade-" + Guid.NewGuid().ToString("n") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite($"Data Source={path}").Options;
            await using var db = new AppDbContext(options);
            await db.Database.ExecuteSqlRawAsync("CREATE TABLE Devices (Id INTEGER NOT NULL CONSTRAINT PK_Devices PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL)");
            await db.Database.ExecuteSqlRawAsync("CREATE TABLE InterfaceStates (DeviceId INTEGER NOT NULL, IfIndex INTEGER NOT NULL, PRIMARY KEY (DeviceId, IfIndex))");
            await db.Database.ExecuteSqlRawAsync("INSERT INTO InterfaceStates (DeviceId, IfIndex) VALUES (1, 7)");
            await SchemaUpgrader.ApplyAsync(db);

            var connection = db.Database.GetDbConnection();
            if (connection.State != ConnectionState.Open)
            {
                await connection.OpenAsync();
            }

            var deviceColumns = await Columns(connection, "Devices");
            var interfaceColumns = await Columns(connection, "InterfaceStates");
            Assert.Contains("IfIncludePattern", deviceColumns);
            Assert.Contains("IfExcludePattern", deviceColumns);
            Assert.Contains("IfExcludeAdminDown", deviceColumns);
            Assert.Contains("HaPendingState", deviceColumns);
            Assert.Contains("HaPendingCount", deviceColumns);
            Assert.Contains("Monitored", interfaceColumns);
            Assert.Contains("MonitorOverride", interfaceColumns);

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT Monitored, MonitorOverride FROM InterfaceStates WHERE IfIndex = 7";
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1L, reader.GetInt64(0));
            Assert.True(reader.IsDBNull(1));
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try
                {
                    File.Delete(path + suffix);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    [Fact]
    public async Task Upgrade_keeps_existing_device_values_as_overrides_and_seeds_global()
    {
        var path = Path.Combine(Path.GetTempPath(), "netsentinel-policy-" + Guid.NewGuid().ToString("n") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite($"Data Source={path}").Options;
            await using var db = new AppDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Devices.Add(new Device
            {
                Name = "edge",
                Host = "10.1.1.1",
                Port = 1161,
                Version = NetSentinel.Core.SnmpVersion.V2C,
                Community = "lab",
                PollIntervalSeconds = 30,
                Enabled = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
            await ForceNotNullAsync(db, "Port");
            await ForceNotNullAsync(db, "Community");
            await db.Database.ExecuteSqlRawAsync("DROP TABLE IF EXISTS MonitorPolicies");

            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Snmp:TimeoutMs"] = "2500",
                ["Snmp:Retries"] = "3",
                ["Snmp:FailureThreshold"] = "2",
                ["Retention:Days"] = "30"
            }).Build();

            await DbInitializer.SeedAsync(db, configuration);

            var device = await db.Devices.SingleAsync();
            Assert.Equal(1161, device.Port);
            Assert.Equal("lab", device.Community);
            Assert.Equal(30, device.PollIntervalSeconds);
            Assert.Null(device.TimeoutMs);
            Assert.Null(device.Retries);
            Assert.Null(device.AlertOnHaChange);
            Assert.Null(device.HaPendingState);
            Assert.Equal(0, device.HaPendingCount);

            var connection = db.Database.GetDbConnection();
            if (connection.State != ConnectionState.Open)
            {
                await connection.OpenAsync();
            }

            await using var info = connection.CreateCommand();
            info.CommandText = "SELECT \"notnull\" FROM pragma_table_info('Devices') WHERE name = 'Port'";
            Assert.Equal(0L, (long)(await info.ExecuteScalarAsync())!);

            var global = await db.Policies.SingleAsync(policy => policy.Scope == "global");
            Assert.Equal("public", global.Community);
            Assert.Equal(161, global.Port);
            Assert.Equal(2500, global.TimeoutMs);
            Assert.Equal(3, global.Retries);
            Assert.True(global.AlertOnHaChange);

            db.Devices.Add(new Device { Name = "new", Host = "10.2.2.2", CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, Location = "FMC" });
            await db.SaveChangesAsync();
            await PolicyStore.EnsureLocationsAsync(db);
            await db.SaveChangesAsync();
            var location = await db.Policies.SingleAsync(policy => policy.Scope == "location" && policy.LocationKey == "FMC");
            Assert.Null(location.Community);
            Assert.Equal("FMC", location.DisplayName);
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try
                {
                    File.Delete(path + suffix);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    [Fact]
    public async Task Upgrade_adds_ha_pending_columns_without_clearing_ha_state()
    {
        var path = Path.Combine(Path.GetTempPath(), "netsentinel-ha-" + Guid.NewGuid().ToString("n") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite($"Data Source={path}").Options;
            await using var db = new AppDbContext(options);
            await db.Database.ExecuteSqlRawAsync(
                "CREATE TABLE Devices (Id INTEGER NOT NULL CONSTRAINT PK_Devices PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, HaState TEXT NULL, HaPeerState TEXT NULL, HaVendor TEXT NULL)");
            await db.Database.ExecuteSqlRawAsync(
                "INSERT INTO Devices (Name, HaState, HaPeerState, HaVendor) VALUES ('fw', 'passive', 'active', 'paloalto')");
            await SchemaUpgrader.ApplyAsync(db);

            var connection = db.Database.GetDbConnection();
            if (connection.State != ConnectionState.Open)
            {
                await connection.OpenAsync();
            }

            var columns = await Columns(connection, "Devices");
            Assert.Contains("HaPendingState", columns);
            Assert.Contains("HaPendingCount", columns);

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT HaState, HaPeerState, HaVendor, HaPendingState, HaPendingCount FROM Devices WHERE Name = 'fw'";
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("passive", reader.GetString(0));
            Assert.Equal("active", reader.GetString(1));
            Assert.Equal("paloalto", reader.GetString(2));
            Assert.True(reader.IsDBNull(3));
            Assert.Equal(0L, reader.GetInt64(4));
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try
                {
                    File.Delete(path + suffix);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private static async Task ForceNotNullAsync(AppDbContext db, string columnName)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        var columns = new List<(string Name, string Type, bool NotNull, string? DefaultSql, int Pk)>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('Devices')";
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                columns.Add((
                    reader.GetString(0),
                    reader.IsDBNull(1) ? "TEXT" : reader.GetString(1),
                    reader.GetInt64(2) == 1,
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? 0 : (int)reader.GetInt64(4)));
            }
        }

        var defs = new List<string>();
        var names = new List<string>();
        foreach (var column in columns)
        {
            var quoted = "\"" + column.Name.Replace("\"", "\"\"") + "\"";
            names.Add(quoted);
            if (column.Pk == 1)
            {
                defs.Add($"{quoted} INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT");
                continue;
            }

            var notNull = column.NotNull || column.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase);
            var fallback = column.DefaultSql is null ? "" : " DEFAULT " + column.DefaultSql;
            defs.Add($"{quoted} {column.Type} {(notNull ? "NOT NULL" : "NULL")}{fallback}");
        }

        var list = string.Join(", ", names);
        async Task Exec(string sql)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        await Exec("PRAGMA foreign_keys=OFF");
        await Exec($"CREATE TABLE \"Devices__force\" ({string.Join(", ", defs)})");
        await Exec($"INSERT INTO \"Devices__force\" ({list}) SELECT {list} FROM \"Devices\"");
        await Exec("DROP TABLE \"Devices\"");
        await Exec("ALTER TABLE \"Devices__force\" RENAME TO \"Devices\"");
        await Exec("PRAGMA foreign_keys=ON");
    }

    private static async Task<HashSet<string>> Columns(System.Data.Common.DbConnection connection, string table)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}')";
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            names.Add(reader.GetString(0));
        }

        return names;
    }
}
