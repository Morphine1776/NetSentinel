using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Data;

namespace NetSentinel.Pages;

public sealed class IndexModel : PageModel
{
    private readonly AppDbContext _db;

    public IndexModel(AppDbContext db)
    {
        _db = db;
    }

    public List<Device> Devices { get; private set; } = new();

    public int Up { get; private set; }

    public int Down { get; private set; }

    public int Pending { get; private set; }

    public async Task OnGetAsync()
    {
        Devices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync();
        foreach (var device in Devices)
        {
            var status = TextFormat.Reachability(device);
            if (status is "Up" or "Degraded")
            {
                Up++;
            }
            else if (status == "Down")
            {
                Down++;
            }
            else
            {
                Pending++;
            }
        }
    }
}
