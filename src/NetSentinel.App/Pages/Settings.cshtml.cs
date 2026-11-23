using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Polling;
using NetSentinel.Services;

namespace NetSentinel.Pages;

public sealed class SettingsModel : PageModel
{
    private readonly AppDbContext _db;
    private readonly RuleService _rules;
    private readonly EmailNotifier _email;
    private readonly TrapWorker _traps;

    public SettingsModel(AppDbContext db, RuleService rules, EmailNotifier email, TrapWorker traps)
    {
        _db = db;
        _rules = rules;
        _email = email;
        _traps = traps;
    }

    [BindProperty]
    public SettingsForm Form { get; set; } = new();

    [BindProperty]
    public RuleInput Rule { get; set; } = new() { Enabled = true };

    public AppSetting Settings { get; private set; } = new();

    public List<AlertRule> Rules { get; private set; } = new();

    public List<Device> Devices { get; private set; } = new();

    public List<CustomOid> Oids { get; private set; } = new();

    public List<string> Errors { get; private set; } = new();

    [TempData]
    public string? Notice { get; set; }

    public async Task OnGetAsync()
    {
        await LoadAsync();
        Form = SettingsForm.From(Settings);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var errors = new List<string>();
        if (Form.RetentionDays is < 1 or > 3650) errors.Add("Retention must be between 1 and 3650 days.");
        if (Form.FailureThreshold is < 1 or > 20) errors.Add("Failure threshold must be between 1 and 20 polls.");
        if (Form.TrapPort is < 1 or > 65535) errors.Add("Trap port must be between 1 and 65535.");
        if (Form.SmtpPort is < 1 or > 65535) errors.Add("SMTP port must be between 1 and 65535.");
        if (Form.SmtpSecurity is not ("None" or "StartTls" or "SslOnConnect")) errors.Add("Choose a valid SMTP security mode.");
        if (errors.Count > 0)
        {
            Errors = errors;
            await LoadAsync();
            return Page();
        }

        var settings = await _db.Settings.OrderBy(item => item.Id).FirstAsync();
        settings.RetentionDays = Form.RetentionDays;
        settings.FailureThreshold = Form.FailureThreshold;
        settings.TrapEnabled = Form.TrapEnabled;
        settings.TrapPort = Form.TrapPort;
        settings.SmtpEnabled = Form.SmtpEnabled;
        settings.SmtpHost = (Form.SmtpHost ?? "").Trim();
        settings.SmtpPort = Form.SmtpPort;
        settings.SmtpUser = (Form.SmtpUser ?? "").Trim();
        if (!string.IsNullOrEmpty(Form.SmtpPassword))
        {
            settings.SmtpPassword = Form.SmtpPassword;
        }

        settings.SmtpFrom = (Form.SmtpFrom ?? "").Trim();
        settings.SmtpTo = (Form.SmtpTo ?? "").Trim();
        settings.SmtpSecurity = Form.SmtpSecurity;
        await _db.SaveChangesAsync();
        await _traps.ReconfigureAsync(HttpContext.RequestAborted);
        Notice = "Settings saved.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRuleAsync()
    {
        var (rule, errors) = await _rules.SaveAsync(Rule);
        if (errors.Count > 0 || rule is null)
        {
            Errors = errors;
            await LoadAsync();
            Form = SettingsForm.From(Settings);
            return Page();
        }

        Notice = "Alert rule saved.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteRuleAsync(int ruleId)
    {
        await _rules.DeleteAsync(ruleId);
        Notice = "Alert rule removed.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostTestEmailAsync()
    {
        try
        {
            await _email.SendTestAsync(HttpContext.RequestAborted);
            Notice = "Test message sent.";
        }
        catch (Exception ex)
        {
            Notice = ex.Message;
        }

        return RedirectToPage();
    }

    private async Task LoadAsync()
    {
        Settings = await _db.Settings.AsNoTracking().OrderBy(item => item.Id).FirstAsync();
        Rules = await _db.Rules.AsNoTracking().OrderBy(rule => rule.Name).ToListAsync();
        Devices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync();
        Oids = await _db.CustomOids.AsNoTracking().Include(oid => oid.Device).OrderBy(oid => oid.Name).ToListAsync();
    }

    public sealed class SettingsForm
    {
        public int RetentionDays { get; set; } = 30;
        public int FailureThreshold { get; set; } = 2;
        public bool TrapEnabled { get; set; } = true;
        public int TrapPort { get; set; } = 1162;
        public bool SmtpEnabled { get; set; }
        public string SmtpHost { get; set; } = "";
        public int SmtpPort { get; set; } = 587;
        public string SmtpUser { get; set; } = "";
        public string? SmtpPassword { get; set; }
        public string SmtpFrom { get; set; } = "";
        public string SmtpTo { get; set; } = "";
        public string SmtpSecurity { get; set; } = "StartTls";

        public static SettingsForm From(AppSetting settings) => new()
        {
            RetentionDays = settings.RetentionDays,
            FailureThreshold = settings.FailureThreshold,
            TrapEnabled = settings.TrapEnabled,
            TrapPort = settings.TrapPort,
            SmtpEnabled = settings.SmtpEnabled,
            SmtpHost = settings.SmtpHost,
            SmtpPort = settings.SmtpPort,
            SmtpUser = settings.SmtpUser,
            SmtpFrom = settings.SmtpFrom,
            SmtpTo = settings.SmtpTo,
            SmtpSecurity = settings.SmtpSecurity
        };
    }
}
