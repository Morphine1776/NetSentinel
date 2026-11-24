using System.Data;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

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
