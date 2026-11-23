using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Pages;

public sealed class TrapsModel : PageModel
{
    private readonly AppDbContext _db;

    public TrapsModel(AppDbContext db)
    {
        _db = db;
    }

    public List<TrapEvent> Traps { get; private set; } = new();

    public AppSetting Settings { get; private set; } = new();

    public async Task OnGetAsync()
    {
        Settings = await _db.Settings.AsNoTracking().OrderBy(item => item.Id).FirstAsync();
        Traps = await _db.Traps.AsNoTracking().OrderByDescending(trap => trap.ReceivedAt).Take(200).ToListAsync();
    }
}
