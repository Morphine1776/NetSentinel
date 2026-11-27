using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Pages.Shared;
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

    [BindProperty]
    public PolicyForm Policy { get; set; } = new();

    public List<string> Errors { get; private set; } = new();

    public List<string> Warnings { get; private set; } = new();

    public List<Device> OtherDevices { get; private set; } = new();

    public ResolvedPolicy Effective { get; private set; } = null!;

    public ResolvedPolicy Inherited { get; private set; } = null!;

    public bool IsNew => Input.Id is null;

    public PolicyEditorModel Editor => new()
    {
        Form = Policy,
        Effective = Effective,
        Inherited = Inherited,
        AllowInherit = true,
        Prefix = "Policy"
    };

    public async Task<IActionResult> OnGetAsync(int? id)
    {
        await LoadOthersAsync();
        if (id is null)
        {
            Input = new DeviceInput { CustomOids = new List<CustomOidInput> { new() } };
            await LoadPolicyAsync(new Device { Location = "" });
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
            Enabled = device.Enabled,
            GroupName = device.GroupName,
            Location = device.Location,
            Tags = device.Tags,
            ParentDeviceId = device.ParentDeviceId,
            V3Context = device.V3Context,
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

        await LoadPolicyAsync(device);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Input.CustomOids ??= new List<CustomOidInput>();
        Policy ??= new PolicyForm();
        var saved = await _devices.SaveAsync(Input, Policy);
        if (!saved.Ok || saved.Device is null)
        {
            Errors = saved.Errors;
            Warnings = saved.Warnings;
            await LoadOthersAsync();
            if (Input.CustomOids.Count == 0)
            {
                Input.CustomOids.Add(new CustomOidInput());
            }

            await LoadPolicyAsync(await PostedPreviewAsync(), keepPosted: true);
            return Page();
        }

        if (saved.Warnings.Count > 0)
        {
            TempData["Warning"] = string.Join(" ", saved.Warnings);
        }

        return Redirect($"/devices/{saved.Device.Id}");
    }

    public async Task<IActionResult> OnPostResetPolicyAsync(int id)
    {
        var device = await _db.Devices.Include(item => item.CustomOids).FirstOrDefaultAsync(item => item.Id == id);
        if (device is null)
        {
            return NotFound();
        }

        PolicyStore.WriteDevice(device, new PolicyValues());
        device.UpdatedAt = DateTime.UtcNow;
        var states = await _db.InterfaceStates.Where(state => state.DeviceId == id).ToListAsync();
        var catalog = await PolicyStore.LoadAsync(_db);
        InterfaceMonitorService.Apply(catalog.Resolve(device).InterfaceRules(), states);
        await _db.SaveChangesAsync();
        TempData["Warning"] = "Policy overrides were cleared. This device now inherits.";
        return RedirectToPage(new { id });
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

    private async Task LoadPolicyAsync(Device device, bool keepPosted = false)
    {
        var catalog = await PolicyStore.LoadAsync(_db);
        Effective = catalog.Resolve(device);
        Inherited = catalog.Resolve(new Device { Location = device.Location });
        if (!keepPosted)
        {
            Policy = PolicyStore.FormFrom(PolicyStore.FromDevice(device), Effective);
        }
    }

    private async Task<Device> PostedPreviewAsync()
    {
        Device device;
        if (Input.Id is int id)
        {
            device = await _db.Devices.AsNoTracking().FirstOrDefaultAsync(item => item.Id == id) ?? new Device();
        }
        else
        {
            device = new Device();
        }

        var written = PolicyStore.ApplyForm(PolicyStore.FromDevice(device), Policy, inheritAllowed: true);
        PolicyStore.WriteDevice(device, written);
        device.Location = Input.Location ?? "";
        return device;
    }
}
