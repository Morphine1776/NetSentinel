using NetSentinel.Core;

namespace NetSentinel.Snmp;

public sealed record CustomOidTarget(int Id, string Name, string Oid);

public sealed record DevicePollTarget(
    string Host,
    int Port,
    SnmpVersion Version,
    string Community,
    string V3User,
    string V3Context,
    string V3AuthProtocol,
    string V3AuthPassword,
    string V3PrivProtocol,
    string V3PrivPassword,
    IReadOnlyList<CustomOidTarget> CustomOids,
    int TimeoutMs,
    int Retries);

public sealed class InterfaceReading
{
    public int IfIndex { get; set; }
    public string IfDescr { get; set; } = "";
    public string IfName { get; set; } = "";
    public string IfAlias { get; set; } = "";
    public int AdminStatus { get; set; }
    public int OperStatus { get; set; }
    public ulong SpeedBps { get; set; }
    public ulong InOctets { get; set; }
    public ulong OutOctets { get; set; }
    public int CounterBits { get; set; } = 32;
}

public sealed class CustomOidReading
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Oid { get; set; } = "";
    public string RawValue { get; set; } = "";
    public double? NumericValue { get; set; }
    public int? CounterBits { get; set; }
    public bool Ok { get; set; }
}

public sealed class PollResult
{
    public bool SnmpOk { get; set; }
    public bool? PingOk { get; set; }
    public string? Error { get; set; }
    public int? ResponseTimeMs { get; set; }
    public string? SysDescr { get; set; }
    public string? SysObjectId { get; set; }
    public string? SysName { get; set; }
    public long? SysUpTimeTicks { get; set; }
    public DateTime SampledAt { get; set; } = DateTime.UtcNow;
    public List<InterfaceReading> Interfaces { get; set; } = new();
    public List<CustomOidReading> CustomOids { get; set; } = new();
    public List<NeighborObservation> Neighbors { get; set; } = new();
    public string? HaState { get; set; }
    public string? HaPeerState { get; set; }
    public string? HaVendor { get; set; }
    public bool HaRead { get; set; }
    public bool HaProbeFailed { get; set; }
}
