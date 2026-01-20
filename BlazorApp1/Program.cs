using BlazorApp1.Components;
using BlazorApp1.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shared.Auth;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Blazor with both Server and WebAssembly support
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options =>
    {
        options.DetailedErrors = true;
    })
    .AddInteractiveWebAssemblyComponents();

// HttpClient to call WebApi
builder.Services.AddHttpClient("WebApi", client =>
{
    client.BaseAddress = new Uri("http://localhost:5100");
});

// Cookie authentication for the Blazor Server
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// Server-side auth state provider that persists state to WASM
builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthStateProvider>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(BlazorApp1.Client._Imports).Assembly);
app.MapPost("/Account/Login", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? returnUrl = null) =>
{
    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/login", new { email, password });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, result.Email!),
                new(ClaimTypes.Email, result.Email!)
            };
            claims.AddRange(result.Roles.Select(r => new Claim(ClaimTypes.Role, r)));

            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                new AuthenticationProperties { IsPersistent = true });

            return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
        }
    }

    return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
});
app.MapPost("/Account/Register", async (
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? firstName,
    [FromForm] string? lastName) =>
{
    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/register", new { email, password, firstName, lastName });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true)
        {
            return Results.Redirect("/Account/Login?message=Registration+successful");
        }

        var errors = string.Join(", ", result?.Errors ?? ["Registration failed"]);
        return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(errors)}");
    }

    return Results.Redirect("/Account/Register?error=Registration+failed");
});
app.MapPost("/Account/Logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});
app.Run();
