using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
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

    public ResolvedPolicy Effective { get; private set; } = null!;

    public PolicyValues StoredPolicy { get; private set; } = new();

    public HaReading Ha { get; private set; } = HaReading.Unavailable;

    public string? FilterError { get; private set; }

    public string? BulkError { get; private set; }

    public string? Warning { get; private set; }

    public async Task<IActionResult> OnGetAsync(int id, int? iface, int? custom, int range = 60, int unmonitored = 0)
    {
        var device = await _db.Devices.AsNoTracking().Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        Device = device;
        Warning = TempData["Warning"] as string;
        var catalog = await PolicyStore.LoadAsync(_db);
        Effective = catalog.Resolve(device);
        StoredPolicy = PolicyStore.FromDevice(device);
        Ha = HaStatus.FromStored(device.HaState, device.HaPeerState, device.HaVendor, device.LastSnmpOk == true);
        Policy = InterfaceMonitorService.ReadInput(Effective);
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

    public async Task<IActionResult> OnPostFiltersAsync(
        int id,
        InterfacePolicyInput policy,
        bool useInclude,
        bool useExclude,
        bool useSyntax,
        bool useMatch,
        bool useAdmin,
        bool useAlias,
        bool useUnmonitor,
        bool unmonitorDown,
        bool showUnmonitored,
        int range = 60,
        int? iface = null,
        int? custom = null)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        var current = PolicyStore.FromDevice(device);
        current.IfIncludePattern = useInclude ? (policy.IncludePattern ?? "").Trim() : null;
        current.IfExcludePattern = useExclude ? (policy.ExcludePattern ?? "").Trim() : null;
        current.IfPatternSyntax = useSyntax ? (policy.Syntax ?? "glob").Trim() : null;
        current.IfMatchFields = useMatch ? InterfaceMonitor.FormatFields(policy.MatchName, policy.MatchDescr, policy.MatchAlias) : null;
        current.ExcludeAdminDown = useAdmin ? policy.ExcludeAdminDown : null;
        current.RequireAlias = useAlias ? policy.RequireAlias : null;
        current.UnmonitorDown = useUnmonitor ? unmonitorDown : null;
        var preview = new Device { Location = device.Location };
        PolicyStore.WriteDevice(preview, current);
        var catalog = await PolicyStore.LoadAsync(_db);
        var error = InterfaceMonitor.Validate(catalog.Resolve(preview).InterfaceRules());
        if (error is null)
        {
            PolicyStore.WriteDevice(device, current);
            device.UpdatedAt = DateTime.UtcNow;
            await PolicyStore.EnsureLocationAsync(_db, device.Location);
            var states = await _db.InterfaceStates.Where(state => state.DeviceId == id).ToListAsync();
            InterfaceMonitorService.Apply(catalog.Resolve(device).InterfaceRules(), states);
            await _db.SaveChangesAsync();
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
