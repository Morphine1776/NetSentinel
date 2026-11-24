using NetSentinel.Core;

namespace NetSentinel.Data;

public sealed class Device
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 161;
    public SnmpVersion Version { get; set; } = SnmpVersion.V2C;
    public string Community { get; set; } = "public";
    public string V3User { get; set; } = "";
    public string V3Context { get; set; } = "";
    public string V3AuthProtocol { get; set; } = "None";
    public string V3AuthPassword { get; set; } = "";
    public string V3PrivProtocol { get; set; } = "None";
    public string V3PrivPassword { get; set; } = "";
    public int PollIntervalSeconds { get; set; } = 60;
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? NextPollAt { get; set; }

    public bool? LastPingOk { get; set; }
    public bool? LastSnmpOk { get; set; }
    public int? LastResponseMs { get; set; }
    public string? LastSysName { get; set; }
    public string? LastSysDescr { get; set; }
    public long? LastSysUpTimeTicks { get; set; }
    public DateTime? LastPollAt { get; set; }
    public string? LastError { get; set; }
    public int ConsecutiveFailures { get; set; }
    public string GroupName { get; set; } = "";
    public string Location { get; set; } = "";
    public string Tags { get; set; } = "";
    public int? ParentDeviceId { get; set; }
    public double? MapX { get; set; }
    public double? MapY { get; set; }
    public string IfIncludePattern { get; set; } = "";
    public string IfExcludePattern { get; set; } = "";
    public string IfPatternSyntax { get; set; } = "glob";
    public string IfMatchFields { get; set; } = "name,descr,alias";
    public bool IfExcludeAdminDown { get; set; }
    public bool IfRequireAlias { get; set; }

    public List<CustomOid> CustomOids { get; set; } = new();
}

public sealed class DeviceLink
{
    public int Id { get; set; }
    public int SourceDeviceId { get; set; }
    public int TargetDeviceId { get; set; }
    public string Kind { get; set; } = "manual";
    public int? LocalIfIndex { get; set; }
    public string LocalPort { get; set; } = "";
    public string RemotePort { get; set; } = "";
    public double? Utilization { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class CustomOid
{
    public int Id { get; set; }
    public int DeviceId { get; set; }
    public Device? Device { get; set; }
    public string Name { get; set; } = "";
    public string Oid { get; set; } = "";
    public string? Unit { get; set; }
    public string? LastRaw { get; set; }
    public double? LastNumeric { get; set; }
    public double? LastRate { get; set; }
    public DateTime? LastAt { get; set; }
}

public sealed class DeviceSample
{
    public long Id { get; set; }
    public int DeviceId { get; set; }
    public DateTime Timestamp { get; set; }
    public bool PingOk { get; set; }
    public bool PingKnown { get; set; }
    public bool SnmpOk { get; set; }
    public int? ResponseMs { get; set; }
    public long? SysUpTimeTicks { get; set; }
}

public sealed class InterfaceState
{
    public int DeviceId { get; set; }
    public int IfIndex { get; set; }
    public string IfDescr { get; set; } = "";
    public string IfName { get; set; } = "";
    public string IfAlias { get; set; } = "";
    public int AdminStatus { get; set; }
    public int OperStatus { get; set; }
    public long SpeedBps { get; set; }
    public long InOctets { get; set; }
    public long OutOctets { get; set; }
    public int CounterBits { get; set; }
    public double? InBps { get; set; }
    public double? OutBps { get; set; }
    public double? InUtil { get; set; }
    public double? OutUtil { get; set; }
    public bool Present { get; set; } = true;
    public bool Monitored { get; set; } = true;
    public bool? MonitorOverride { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class InterfaceSample
{
    public long Id { get; set; }
    public int DeviceId { get; set; }
    public int IfIndex { get; set; }
    public DateTime Timestamp { get; set; }
    public int OperStatus { get; set; }
    public double? InBps { get; set; }
    public double? OutBps { get; set; }
    public double? InUtil { get; set; }
    public double? OutUtil { get; set; }
}

public sealed class CustomOidSample
{
    public long Id { get; set; }
    public int DeviceId { get; set; }
    public int CustomOidId { get; set; }
    public DateTime Timestamp { get; set; }
    public string RawValue { get; set; } = "";
    public double? NumericValue { get; set; }
    public double? RatePerSecond { get; set; }
    public int? CounterBits { get; set; }
}

public sealed class TrapEvent
{
    public long Id { get; set; }
    public DateTime ReceivedAt { get; set; }
    public string Source { get; set; } = "";
    public string Version { get; set; } = "";
    public string SecurityName { get; set; } = "";
    public string TrapOid { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Varbinds { get; set; } = "";
}

public enum AlertState
{
    Open = 0,
    Acknowledged = 1,
    Resolved = 2
}

public sealed class AlertEvent
{
    public long Id { get; set; }
    public int? DeviceId { get; set; }
    public string DedupKey { get; set; } = "";
    public AlertKind Kind { get; set; }
    public AlertSeverity Severity { get; set; }
    public string Message { get; set; } = "";
    public AlertState State { get; set; }
    public int? IfIndex { get; set; }
    public int? RuleId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? AcknowledgedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
}

public sealed class AlertRule
{
    public int Id { get; set; }
    public int? DeviceId { get; set; }
    public string Name { get; set; } = "";
    public string Metric { get; set; } = "response_ms";
    public string? InterfaceFilter { get; set; }
    public ThresholdOperator Operator { get; set; } = ThresholdOperator.GreaterThan;
    public double Threshold { get; set; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Warning;
    public bool Enabled { get; set; } = true;
}

public sealed class AppSetting
{
    public int Id { get; set; }
    public int RetentionDays { get; set; } = 30;
    public int FailureThreshold { get; set; } = 2;
    public bool TrapEnabled { get; set; } = true;
    public int TrapPort { get; set; } = 1162;
    public bool SmtpEnabled { get; set; }
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUser { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public string SmtpFrom { get; set; } = "";
    public string SmtpTo { get; set; } = "";
    public string SmtpSecurity { get; set; } = "StartTls";
}
