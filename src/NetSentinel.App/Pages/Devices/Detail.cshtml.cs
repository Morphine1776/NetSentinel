using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;
using NetSentinel.Services;

namespace NetSentinel.Pages.Devices;

public sealed class DetailModel : PageModel
{
    private static readonly int[] Ranges = { 60, 360, 1440, 10080 };
    private readonly AppDbContext _db;
    private readonly InterfaceMonitorService _monitor;

    public DetailModel(AppDbContext db, InterfaceMonitorService monitor)
    {
        _db = db;
        _monitor = monitor;
    }

    public Device Device { get; private set; } = null!;

    public List<InterfaceState> Interfaces { get; private set; } = new();

    public int Range { get; private set; } = 60;

    public int? SelectedInterface { get; private set; }

    public int? SelectedCustom { get; private set; }

    public bool ShowUnmonitored { get; private set; }

    public int MonitoredCount { get; private set; }

    public int UnmonitoredCount { get; private set; }

    public InterfacePolicyInput Policy { get; set; } = new();

    public string? FilterError { get; private set; }

    public string? BulkError { get; private set; }

    public async Task<IActionResult> OnGetAsync(int id, int? iface, int? custom, int range = 60, int unmonitored = 0)
    {
        var device = await _db.Devices.AsNoTracking().Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        Device = device;
        Policy = InterfaceMonitorService.ReadInput(device);
        ShowUnmonitored = unmonitored == 1;
        var present = await _db.InterfaceStates.AsNoTracking()
            .Where(item => item.DeviceId == id && item.Present)
            .OrderBy(item => item.IfIndex)
            .ToListAsync();
        UnmonitoredCount = present.Count(item => !item.Monitored);
        MonitoredCount = present.Count - UnmonitoredCount;
        Interfaces = ShowUnmonitored ? present : present.Where(item => item.Monitored).ToList();
        Range = Ranges.Contains(range) ? range : 60;
        SelectedInterface = iface is int index && Interfaces.Any(item => item.IfIndex == index)
            ? index
            : Interfaces
                .OrderByDescending(item => item.OperStatus == 1)
                .ThenByDescending(item => (item.InBps ?? 0) + (item.OutBps ?? 0))
                .Select(item => (int?)item.IfIndex)
                .FirstOrDefault();
        SelectedCustom = custom is int oid && device.CustomOids.Any(item => item.Id == oid)
            ? oid
            : device.CustomOids.FirstOrDefault()?.Id;
        return Page();
    }

    public async Task<IActionResult> OnPostFiltersAsync(int id, InterfacePolicyInput policy, bool showUnmonitored, int range = 60, int? iface = null, int? custom = null)
    {
        var error = await _monitor.SavePolicyAsync(id, policy, HttpContext.RequestAborted);
        if (error is null)
        {
            return RedirectToPage(new { id, range, iface, custom, unmonitored = showUnmonitored ? 1 : 0 });
        }

        FilterError = error;
        var result = await OnGetAsync(id, iface, custom, range, showUnmonitored ? 1 : 0);
        Policy = policy;
        return result;
    }

    public async Task<IActionResult> OnPostBulkAsync(int id, string? action, int[]? selected, bool showUnmonitored, int range = 60, int? iface = null, int? custom = null)
    {
        var error = await _monitor.BulkAsync(id, action, selected, HttpContext.RequestAborted);
        if (error is null)
        {
            return RedirectToPage(new { id, range, iface, custom, unmonitored = showUnmonitored ? 1 : 0 });
        }

        BulkError = error;
        return await OnGetAsync(id, iface, custom, range, showUnmonitored ? 1 : 0);
    }
}
