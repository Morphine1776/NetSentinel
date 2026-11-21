using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Pages;

public sealed class AlertsModel : PageModel
{
    private readonly AppDbContext _db;

    public AlertsModel(AppDbContext db)
    {
        _db = db;
    }

    public List<AlertRow> Alerts { get; private set; } = new();

    public string State { get; private set; } = "open";

    public async Task OnGetAsync(string? state)
    {
        State = string.Equals(state, "all", StringComparison.OrdinalIgnoreCase) ? "all" : "open";
        await LoadAsync();
    }

    public async Task<IActionResult> OnPostAcknowledgeAsync(long id, string? state)
    {
        var alert = await _db.Alerts.FirstOrDefaultAsync(item => item.Id == id);
        if (alert is { State: AlertState.Open })
        {
            alert.State = AlertState.Acknowledged;
            alert.AcknowledgedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }

        return RedirectToPage(new { state });
    }

    public async Task<IActionResult> OnPostResolveAsync(long id, string? state)
    {
        var alert = await _db.Alerts.FirstOrDefaultAsync(item => item.Id == id);
        if (alert is not null && alert.State != AlertState.Resolved)
        {
            alert.State = AlertState.Resolved;
            alert.ResolvedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }

        return RedirectToPage(new { state });
    }

    private async Task LoadAsync()
    {
        var query = _db.Alerts.AsNoTracking().AsQueryable();
        if (State != "all")
        {
            query = query.Where(alert => alert.State != AlertState.Resolved);
        }

        var alerts = await query.OrderByDescending(alert => alert.CreatedAt).Take(300).ToListAsync();
        var names = await _db.Devices.AsNoTracking().ToDictionaryAsync(device => device.Id, device => device.Name);
        Alerts = alerts.Select(alert => new AlertRow(alert, alert.DeviceId is int id && names.TryGetValue(id, out var name) ? name : "—")).ToList();
    }

    public sealed record AlertRow(AlertEvent Alert, string DeviceName);
}
