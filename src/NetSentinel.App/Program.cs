using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Cookies;
using NetSentinel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting.WindowsServices;
using NetSentinel.Data;
using NetSentinel.Polling;
using NetSentinel.Services;
using NetSentinel.Snmp;
using NetSentinel.Web;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

if (OperatingSystem.IsWindows())
{
    builder.Host.UseWindowsService(options => options.ServiceName = "NetSentinel");
}

var databasePath = builder.Configuration["Database:Path"];
if (string.IsNullOrWhiteSpace(databasePath))
{
    databasePath = Path.Combine("data", "netsentinel.db");
}

if (!Path.IsPathRooted(databasePath))
{
    databasePath = Path.Combine(builder.Environment.ContentRootPath, databasePath);
}

var databaseDirectory = Path.GetDirectoryName(databasePath);
if (!string.IsNullOrEmpty(databaseDirectory))
{
    Directory.CreateDirectory(databaseDirectory);
}

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite($"Data Source={databasePath};Cache=Shared")
        .AddInterceptors(new SqlitePragmaInterceptor()));

builder.Services.Configure<DashboardOptions>(builder.Configuration.GetSection("Dashboard"));
builder.Services.Configure<SnmpOptions>(builder.Configuration.GetSection("Snmp"));
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddSingleton<DevicePoller>();
builder.Services.AddSingleton<TrapWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<TrapWorker>());
builder.Services.AddHostedService<PollWorker>();
builder.Services.AddHostedService<RetentionWorker>();
builder.Services.AddScoped<DeviceAdminService>();
builder.Services.AddScoped<RuleService>();
builder.Services.AddScoped<EmailNotifier>();
builder.Services.AddScoped<ImportService>();
builder.Services.AddScoped<MapService>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/login";
        options.Cookie.Name = "NetSentinel.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Login");
    options.Conventions.AllowAnonymousToPage("/Logout");
    options.Conventions.AllowAnonymousToPage("/Error");
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    database.Database.EnsureCreated();
    await DbInitializer.SeedAsync(database, app.Configuration);
}

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
}

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    var method = context.Request.Method;
    var mutating = HttpMethods.IsPost(method) || HttpMethods.IsPut(method) || HttpMethods.IsDelete(method);
    if (mutating && context.Request.Path.StartsWithSegments("/api") && context.Request.Headers["X-NetSentinel"] != "1")
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsync("Missing X-NetSentinel header.");
        return;
    }

    await next();
});
app.UseAuthorization();

app.MapGet("/health", () => Results.Json(new { status = "ok" })).AllowAnonymous();
app.MapNetSentinelApi();
app.MapRazorPages();

app.Lifetime.ApplicationStarted.Register(() =>
{
    var configured = app.Configuration["Urls"] ?? "http://localhost:8741";
    var listening = app.Urls.Count > 0 ? string.Join(", ", app.Urls) : configured;
    app.Logger.LogInformation("NetSentinel dashboard is ready at {Urls}", listening);
});

app.Run();
