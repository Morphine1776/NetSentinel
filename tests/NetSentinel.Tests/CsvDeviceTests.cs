using NetSentinel.Core;

namespace NetSentinel.Tests;

public class CsvDeviceTests
{
    private static readonly ExistingDeviceRef[] Inventory =
    {
        new(1, "Loopback simulator", "127.0.0.1", 1161, null),
        new(2, "Border", "10.0.0.9", 161, 1)
    };

    [Fact]
    public void Headers_are_case_insensitive_and_unordered()
    {
        const string csv = "PORT,Name,Community,HOST\r\n161,Access,public,10.1.1.5\n";
        var preview = CsvDevices.Preview(csv, Inventory);
        var row = Assert.Single(preview.Rows);
        Assert.Equal(CsvRowStatus.Ready, row.Status);
        Assert.Equal("Access", row.Name);
        Assert.Equal("10.1.1.5", row.Host);
        Assert.Equal("161", row.Port);
    }

    [Fact]
    public void Quoted_commas_and_escaped_quotes_round_trip()
    {
        const string csv = "name,host,community,tags\r\n\"Core, west\",\"10.0.0.1\",\"pub\"\"lic\",\"a, b\"\r\n";
        var parsed = CsvDevices.Parse(csv);
        var row = Assert.Single(parsed);
        Assert.Equal("Core, west", row.Name);
        Assert.Equal("pub\"lic", row.Community);
        Assert.Equal("a, b", row.Tags);
    }

    [Fact]
    public void Missing_name_and_bad_port_are_row_errors()
    {
        const string csv = "name,host,port,community\n,10.0.0.2,99999,public\n";
        var row = Assert.Single(CsvDevices.Preview(csv, Inventory).Rows);
        Assert.Equal(CsvRowStatus.Error, row.Status);
        Assert.Contains(row.Errors, error => error.Contains("Name"));
        Assert.Contains(row.Errors, error => error.Contains("Port"));
    }

    [Fact]
    public void Duplicate_host_against_inventory_is_marked()
    {
        const string csv = "name,host,port,community\nRenamed,127.0.0.1,1161,public\n";
        var row = Assert.Single(CsvDevices.Preview(csv, Inventory).Rows);
        Assert.Equal(CsvRowStatus.Duplicate, row.Status);
        Assert.Equal(1, row.ExistingDeviceId);
        Assert.Equal("host", row.DuplicateMatch);
    }

    [Fact]
    public void Duplicate_name_inside_the_file_is_an_error()
    {
        const string csv = "name,host,community\nSame,10.0.0.2,public\nSame,10.0.0.3,public\n";
        var rows = CsvDevices.Preview(csv, Array.Empty<ExistingDeviceRef>()).Rows;
        Assert.Equal(CsvRowStatus.Ready, rows[0].Status);
        Assert.Equal(CsvRowStatus.Error, rows[1].Status);
        Assert.Contains(rows[1].Errors, error => error.Contains("line 2"));
    }

    [Fact]
    public void Unknown_parent_is_an_error_and_a_later_row_is_a_valid_parent()
    {
        const string csv = "name,host,community,parent\nChild,10.0.0.4,public,Missing\nChild2,10.0.0.5,public,Core switch\nCore switch,10.0.0.1,public,\n";
        var rows = CsvDevices.Preview(csv, Array.Empty<ExistingDeviceRef>()).Rows;
        Assert.Equal(CsvRowStatus.Error, rows[0].Status);
        Assert.Equal(CsvRowStatus.Ready, rows[1].Status);
        Assert.Equal(CsvRowStatus.Ready, rows[2].Status);
    }

    [Fact]
    public void Parent_cycle_is_rejected()
    {
        const string csv = "name,host,community,parent\nA,10.0.0.1,public,B\nB,10.0.0.2,public,A\n";
        var rows = CsvDevices.Preview(csv, Array.Empty<ExistingDeviceRef>()).Rows;
        Assert.All(rows, row => Assert.Contains(row.Errors, error => error.Contains("cycle")));
    }

    [Fact]
    public void Too_many_rows_is_a_file_error()
    {
        var lines = new List<string> { "name,host,community" };
        for (var i = 0; i < CsvDevices.MaxRows + 1; i++)
        {
            lines.Add($"n{i},10.0.{i / 256}.{i % 256},public");
        }

        var preview = CsvDevices.Preview(string.Join("\n", lines), Array.Empty<ExistingDeviceRef>());
        Assert.Contains("1000", preview.FileError);
        Assert.Empty(preview.Rows);
    }

    [Fact]
    public void Bom_and_blank_lines_are_ignored()
    {
        const string csv = "\uFEFFname,host,community\r\n\r\nEdge,10.9.9.9,public\r\n\r\n";
        var row = Assert.Single(CsvDevices.Preview(csv, Array.Empty<ExistingDeviceRef>()).Rows);
        Assert.Equal("Edge", row.Name);
        Assert.Equal(3, row.Line);
    }

    [Fact]
    public void V3_short_password_is_an_error()
    {
        const string csv = "name,host,version,v3_user,v3_auth_protocol,v3_auth_password\nR,10.0.0.8,v3,monitor,SHA256,short\n";
        var row = Assert.Single(CsvDevices.Preview(csv, Array.Empty<ExistingDeviceRef>()).Rows);
        Assert.Equal(CsvRowStatus.Error, row.Status);
        Assert.Contains(row.Errors, error => error.Contains("8 characters"));
    }
}
