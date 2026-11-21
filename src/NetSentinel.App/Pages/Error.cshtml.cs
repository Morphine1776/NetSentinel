using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace NetSentinel.Pages;

[AllowAnonymous]
public sealed class ErrorModel : PageModel
{
    public void OnGet()
    {
    }
}
