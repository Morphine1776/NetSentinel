using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Services;

namespace NetSentinel.Pages.Devices;

public sealed class EditModel : PageModel
{
    private readonly AppDbContext _db;
    private readonly DeviceAdminService _devices;

    public EditModel(AppDbContext db, DeviceAdminService devices)
    {
        _db = db;
        _devices = devices;
    }

    [BindProperty]
    public DeviceInput Input { get; set; } = new();

    public List<string> Errors { get; private set; } = new();

    public List<Device> OtherDevices { get; private set; } = new();

    public bool IsNew => Input.Id is null;

    public async Task<IActionResult> OnGetAsync(int? id)
    {
        await LoadOthersAsync();
        if (id is null)
        {
            Input = new DeviceInput { CustomOids = new List<CustomOidInput> { new() } };
            return Page();
        }

        var device = await _db.Devices.AsNoTracking().Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        Input = new DeviceInput
        {
            Id = device.Id,
            Name = device.Name,
            Host = device.Host,
            Port = device.Port,
            Version = device.Version,
            Community = device.Community,
            V3User = device.V3User,
            V3Context = device.V3Context,
            V3AuthProtocol = device.V3AuthProtocol,
            V3PrivProtocol = device.V3PrivProtocol,
            PollIntervalSeconds = device.PollIntervalSeconds,
            Enabled = device.Enabled,
            GroupName = device.GroupName,
            Location = device.Location,
            Tags = device.Tags,
            ParentDeviceId = device.ParentDeviceId,
            CustomOids = device.CustomOids.Select(oid => new CustomOidInput
            {
                Id = oid.Id,
                Name = oid.Name,
                Oid = oid.Oid,
                Unit = oid.Unit
            }).ToList()
        };
        if (Input.CustomOids.Count == 0)
        {
            Input.CustomOids.Add(new CustomOidInput());
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Input.CustomOids ??= new List<CustomOidInput>();
        var saved = await _devices.SaveAsync(Input);
        if (!saved.Ok || saved.Device is null)
        {
            Errors = saved.Errors;
            await LoadOthersAsync();
            if (Input.CustomOids.Count == 0)
            {
                Input.CustomOids.Add(new CustomOidInput());
            }

            return Page();
        }

        return Redirect($"/devices/{saved.Device.Id}");
    }

    public async Task<IActionResult> OnPostDeleteAsync(int id)
    {
        await _devices.DeleteAsync(id);
        return RedirectToPage("/Index");
    }

    private async Task LoadOthersAsync()
    {
        OtherDevices = await _db.Devices.AsNoTracking().OrderBy(device => device.Name).ToListAsync();
    }
}
