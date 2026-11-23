using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace NetSentinel.Pages;

[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly DashboardOptions _options;

    public LoginModel(IOptions<DashboardOptions> options)
    {
        _options = options.Value;
    }

    [BindProperty]
    public string Username { get; set; } = "";

    [BindProperty]
    public string Password { get; set; } = "";

    public string? Error { get; private set; }

    public bool ShowHint { get; private set; }

    public void OnGet()
    {
        ShowHint = Environment.IsDevelopment();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl)
    {
        ShowHint = Environment.IsDevelopment();
        if (!DashboardAuth.Verify(Username, Password, _options.Username, _options.Password))
        {
            Error = "Those credentials are not recognized.";
            return Page();
        }

        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.Name, Username.Trim()) },
            CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToPage("/Index");
    }

    private IWebHostEnvironment Environment => HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();
}
