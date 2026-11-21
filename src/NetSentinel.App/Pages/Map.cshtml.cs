using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Pages;

public sealed class MapModel : PageModel
{
    private readonly AppDbContext _db;

    public MapModel(AppDbContext db)
    {
        _db = db;
    }

    public List<Device> Devices { get; private set; } = new();

    public async Task OnGetAsync()
    {
        Devices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync();
    }
}
