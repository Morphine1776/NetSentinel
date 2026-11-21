using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Pages.Devices;

public sealed class DetailModel : PageModel
{
    private static readonly int[] Ranges = { 60, 360, 1440, 10080 };
    private readonly AppDbContext _db;

    public DetailModel(AppDbContext db)
    {
        _db = db;
    }

    public Device Device { get; private set; } = null!;

    public List<InterfaceState> Interfaces { get; private set; } = new();

    public int Range { get; private set; } = 60;

    public int? SelectedInterface { get; private set; }

    public int? SelectedCustom { get; private set; }

    public async Task<IActionResult> OnGetAsync(int id, int? iface, int? custom, int range = 60)
    {
        var device = await _db.Devices.AsNoTracking().Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        Device = device;
        Interfaces = await _db.InterfaceStates.AsNoTracking()
            .Where(item => item.DeviceId == id && item.Present)
            .OrderBy(item => item.IfIndex)
            .ToListAsync();
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
}
