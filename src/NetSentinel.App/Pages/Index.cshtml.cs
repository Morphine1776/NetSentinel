using Microsoft.AspNetCore.Mvc.RazorPages;
using NetSentinel.Data;
using NetSentinel.Services;

namespace NetSentinel.Pages;

public sealed class IndexModel : PageModel
{
    private readonly AppDbContext _db;

    public IndexModel(AppDbContext db)
    {
        _db = db;
    }

    public DeviceBoard Board { get; private set; } = new(0, 0, 0, 0, Array.Empty<DeviceBoardGroup>());

    public string BoardJson { get; private set; } = "{}";

    public async Task OnGetAsync()
    {
        Board = await DeviceBoardBuilder.LoadAsync(_db);
        BoardJson = DeviceBoardBuilder.ToJson(Board);
    }
}
