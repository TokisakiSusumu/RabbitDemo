using BlazorApp1.Client.Services;
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
    .AddInteractiveServerComponents(options => options.DetailedErrors = true)
    .AddInteractiveWebAssemblyComponents();

// HttpClient to call WebApi
builder.Services.AddHttpClient("WebApi", client =>
{
    client.BaseAddress = new Uri("http://localhost:5100");
});

// Cookie authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;

        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = context =>
            {
                var email = context.Principal?.Identity?.Name;
                if (email == null)
                {
                    Console.WriteLine("[COOKIE] No user in cookie, rejecting");
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                // If server restarted, token cache is empty → force re-login
                var cache = context.HttpContext.RequestServices.GetRequiredService<TokenCacheService>();
                if (!cache.HasTokens(email))
                {
                    Console.WriteLine($"[COOKIE] No cached tokens for {email} (server restart?), rejecting → re-login");
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// ===== Register Services =====
builder.Services.AddSingleton<TokenCacheService>();  // Singleton: shared across all requests
builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthStateProvider>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IApiClient, ServerApiClient>();  // Server-side: direct JWT calls

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

// =====================================================================
//  AUTH ENDPOINTS (Login, Register, Logout)
// =====================================================================

app.MapPost("/Account/Login", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    TokenCacheService tokenCache,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? returnUrl = null) =>
{
    Console.WriteLine($"[LOGIN] {email} - calling WebApi...");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/login", new { email, password });

    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($"[LOGIN] {email} - FAILED: {response.StatusCode}");
        return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
    }

    var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
    if (result?.Success != true || result.Token == null || result.RefreshToken == null)
    {
        Console.WriteLine($"[LOGIN] {email} - FAILED: API returned success=false");
        return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
    }

    Console.WriteLine($"[LOGIN] {email} - SUCCESS, roles=[{string.Join(",", result.Roles)}], access expires {result.Expiration:HH:mm:ss} UTC");

    // 1. Store tokens in SERVER-SIDE CACHE (not cookie!)
    var tokenData = new TokenData
    {
        AccessToken = result.Token,
        RefreshToken = result.RefreshToken,
        AccessTokenExpiry = result.Expiration ?? DateTime.UtcNow.AddMinutes(1),
        RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
    };
    tokenCache.Store(result.Email!, tokenData);

    // 2. Cookie only stores identity claims (Name, Email, Roles) - NO tokens
    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, result.Email!),
        new(ClaimTypes.Email, result.Email!)
    };
    claims.AddRange(result.Roles.Select(r => new Claim(ClaimTypes.Role, r)));

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
        new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
        });

    Console.WriteLine($"[LOGIN] {email} - cookie set, redirecting to {returnUrl ?? "/"}");
    return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
});

app.MapPost("/Account/Register", async (
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? firstName,
    [FromForm] string? lastName) =>
{
    Console.WriteLine($"[REGISTER] {email}");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/register", new { email, password, firstName, lastName });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true)
        {
            Console.WriteLine($"[REGISTER] {email} - SUCCESS");
            return Results.Redirect("/Account/Login?message=Registration+successful");
        }

        var errors = string.Join(", ", result?.Errors ?? ["Registration failed"]);
        return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(errors)}");
    }

    Console.WriteLine($"[REGISTER] {email} - FAILED");
    return Results.Redirect("/Account/Register?error=Registration+failed");
});

app.MapPost("/Account/Logout", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    TokenCacheService tokenCache) =>
{
    var email = context.User.Identity?.Name;
    Console.WriteLine($"[LOGOUT] {email}");

    // Try to revoke tokens on backend
    if (email != null)
    {
        var tokenData = tokenCache.Get(email);
        if (tokenData != null)
        {
            try
            {
                var client = httpClientFactory.CreateClient("WebApi");
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenData.AccessToken);
                _ = client.PostAsync("api/auth/logout", null);
            }
            catch { /* Don't block logout */ }
        }

        tokenCache.Remove(email);
    }

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    Console.WriteLine($"[LOGOUT] {email} - done");
    return Results.Redirect("/");
});

// =====================================================================
//  BFF PROXY ENDPOINTS (for WASM components to call WebApi)
// =====================================================================

app.MapGet("/api/bff/me", async (HttpContext context, IAuthService authService) =>
{
    var email = context.User.Identity?.Name;
    if (email == null) return Results.Unauthorized();

    Console.WriteLine($"[BFF] GET /api/bff/me for {email}");
    var userInfo = await authService.GetAsync<UserInfo>("api/auth/me");

    if (userInfo == null)
        return Results.StatusCode(502); // Gateway error - WebApi call failed

    return Results.Ok(userInfo);
}).RequireAuthorization();

app.MapPost("/api/bff/refresh", async (HttpContext context, IAuthService authService) =>
{
    var email = context.User.Identity?.Name;
    if (email == null) return Results.Unauthorized();

    Console.WriteLine($"[BFF] POST /api/bff/refresh for {email}");
    var success = await authService.RefreshTokenAsync();

    return success ? Results.Ok() : Results.StatusCode(502);
}).RequireAuthorization();

app.Run();
