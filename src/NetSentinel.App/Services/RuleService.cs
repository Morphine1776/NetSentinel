using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;

namespace NetSentinel.Services;

public sealed class RuleInput
{
    public int? Id { get; set; }
    public int? DeviceId { get; set; }
    public string Name { get; set; } = "";
    public string Metric { get; set; } = "response_ms";
    public string? InterfaceFilter { get; set; }
    public ThresholdOperator Operator { get; set; } = ThresholdOperator.GreaterThan;
    public double Threshold { get; set; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Warning;
    public bool Enabled { get; set; } = true;
}

public sealed class RuleService
{
    private static readonly HashSet<string> Metrics = new(StringComparer.Ordinal)
    {
        "response_ms", "in_bps", "out_bps", "in_util", "out_util"
    };

    private readonly AppDbContext _db;

    public RuleService(AppDbContext db)
    {
        _db = db;
    }

    public async Task<(AlertRule? Rule, List<string> Errors)> SaveAsync(RuleInput input, CancellationToken cancellationToken = default)
    {
        var errors = new List<string>();
        input.Name = (input.Name ?? "").Trim();
        input.Metric = (input.Metric ?? "").Trim();
        input.InterfaceFilter = string.IsNullOrWhiteSpace(input.InterfaceFilter) ? null : input.InterfaceFilter.Trim();

        if (input.Name.Length is < 1 or > 80)
        {
            errors.Add("Rule name must be 1–80 characters.");
        }

        if (!IsMetric(input.Metric))
        {
            errors.Add("Choose a supported metric.");
        }

        if (double.IsNaN(input.Threshold) || double.IsInfinity(input.Threshold))
        {
            errors.Add("Threshold must be a finite number.");
        }

        if (input.DeviceId is int deviceId && !await _db.Devices.AnyAsync(d => d.Id == deviceId, cancellationToken))
        {
            errors.Add("The selected device does not exist.");
        }

        if (errors.Count > 0)
        {
            return (null, errors);
        }

        var rule = input.Id is int id
            ? await _db.Rules.FirstOrDefaultAsync(r => r.Id == id, cancellationToken)
            : new AlertRule();
        if (rule is null)
        {
            return (null, new List<string> { "That rule no longer exists." });
        }

        rule.Name = input.Name;
        rule.DeviceId = input.DeviceId;
        rule.Metric = input.Metric;
        rule.InterfaceFilter = input.InterfaceFilter;
        rule.Operator = input.Operator;
        rule.Threshold = input.Threshold;
        rule.Severity = input.Severity;
        rule.Enabled = input.Enabled;
        if (rule.Id == 0)
        {
            _db.Rules.Add(rule);
        }

        await _db.SaveChangesAsync(cancellationToken);
        return (rule, errors);
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        await _db.Rules.Where(r => r.Id == id).ExecuteDeleteAsync(cancellationToken);
    }

    public static bool IsMetric(string metric)
    {
        if (Metrics.Contains(metric))
        {
            return true;
        }

        if (metric.StartsWith("custom:", StringComparison.Ordinal) || metric.StartsWith("custom_rate:", StringComparison.Ordinal))
        {
            var prefix = metric.StartsWith("custom_rate:", StringComparison.Ordinal) ? "custom_rate:" : "custom:";
            return int.TryParse(metric[prefix.Length..], out var id) && id > 0;
        }

        return false;
    }
}
