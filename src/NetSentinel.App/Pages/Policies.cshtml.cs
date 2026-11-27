using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NetSentinel.Core;
using NetSentinel.Data;
using NetSentinel.Pages.Shared;
using NetSentinel.Services;

namespace NetSentinel.Pages;

public sealed class PoliciesModel : PageModel
{
    private readonly AppDbContext _db;

    public PoliciesModel(AppDbContext db)
    {
        _db = db;
    }

    [BindProperty]
    public PolicyForm GlobalForm { get; set; } = new();

    [BindProperty]
    public PolicyForm LocationForm { get; set; } = new();

    [BindProperty]
    public string LocationKey { get; set; } = "";

    public List<string> Errors { get; private set; } = new();

    public string? Saved { get; private set; }

    public ResolvedPolicy GlobalEffective { get; private set; } = null!;

    public ResolvedPolicy? LocationEffective { get; private set; }

    public string LocationName { get; private set; } = "";

    public IReadOnlyList<(string Key, string Display)> LocationChoices { get; private set; } = Array.Empty<(string, string)>();

    public PolicyEditorModel GlobalEditor => new()
    {
        Form = GlobalForm,
        Effective = GlobalEffective,
        AllowInherit = false,
        Prefix = "GlobalForm"
    };

    public PolicyEditorModel? LocationEditor => LocationEffective is null
        ? null
        : new PolicyEditorModel
        {
            Form = LocationForm,
            Effective = LocationEffective,
            Inherited = GlobalEffective,
            AllowInherit = true,
            Prefix = "LocationForm"
        };

    public async Task OnGetAsync(string? location, string? saved)
    {
        Saved = saved;
        await LoadAsync(location, keepForms: false);
    }

    public async Task<IActionResult> OnPostGlobalAsync()
    {
        var row = await _db.Policies.FirstAsync(policy => policy.Scope == "global");
        var written = PolicyStore.ApplyForm(PolicyStore.FromPolicy(row), GlobalForm, inheritAllowed: false);
        var resolved = PolicyResolver.Resolve(written, null, null, "Global");
        var errors = PolicyStore.Validate(resolved, written, requireConcrete: true);
        if (errors.Count > 0)
        {
            Errors = errors;
            await LoadAsync(LocationKey, keepForms: true);
            GlobalEffective = resolved;
            return Page();
        }

        PolicyStore.WritePolicy(row, written);
        await _db.SaveChangesAsync();
        return RedirectToPage(new { location = LocationKey, saved = "global" });
    }

    public async Task<IActionResult> OnPostLocationAsync()
    {
        var key = string.Equals(LocationKey, "unassigned", StringComparison.OrdinalIgnoreCase) ? "" : LocationGroups.KeyFor(LocationKey);
        var row = await _db.Policies.FirstOrDefaultAsync(policy => policy.Scope == "location" && policy.LocationKey == key);
        if (row is null)
        {
            return NotFound();
        }

        var global = PolicyStore.FromPolicy(await _db.Policies.AsNoTracking().FirstAsync(policy => policy.Scope == "global"));
        var written = PolicyStore.ApplyForm(PolicyStore.FromPolicy(row), LocationForm, inheritAllowed: true);
        var resolved = PolicyResolver.Resolve(global, written, null, row.DisplayName);
        var errors = PolicyStore.Validate(resolved, written, requireConcrete: false);
        if (errors.Count > 0)
        {
            Errors = errors;
            await LoadAsync(key, keepForms: true);
            LocationEffective = resolved;
            return Page();
        }

        PolicyStore.WritePolicy(row, written);
        await _db.SaveChangesAsync();
        return RedirectToPage(new { location = key, saved = "location" });
    }

    private async Task LoadAsync(string? location, bool keepForms)
    {
        await PolicyStore.EnsureLocationsAsync(_db);
        await _db.SaveChangesAsync();
        var catalog = await PolicyStore.LoadAsync(_db);
        GlobalEffective = PolicyResolver.Resolve(catalog.Global, null, null, "Global");
        if (!keepForms)
        {
            GlobalForm = PolicyStore.FormFrom(catalog.Global, GlobalEffective);
        }

        LocationChoices = catalog.Locations.Select(item => (item.Key, item.Display)).ToList();
        var key = location ?? "";
        if (string.Equals(key, "unassigned", StringComparison.OrdinalIgnoreCase))
        {
            key = "";
        }
        else if (key.Length > 0)
        {
            key = LocationGroups.KeyFor(key);
        }

        if (!catalog.TryLocation(key, out var display, out var values) && LocationChoices.Count > 0 && string.IsNullOrEmpty(location))
        {
            var first = LocationChoices[0];
            key = first.Key;
            catalog.TryLocation(key, out display, out values);
        }

        if (LocationChoices.Count == 0)
        {
            return;
        }

        LocationKey = key;
        LocationName = display;
        LocationEffective = PolicyResolver.Resolve(catalog.Global, values, null, display);
        if (!keepForms)
        {
            LocationForm = PolicyStore.FormFrom(values, LocationEffective);
        }
    }
}
