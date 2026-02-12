using BlazorApp1.Client.Services;
using BlazorApp1.Components;
using BlazorApp1.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shared.Auth;
using System.Net.Http.Headers;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options => options.DetailedErrors = true)
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddHttpClient("WebApi", client =>
{
    client.BaseAddress = new Uri("http://localhost:5100");
});

// Read session config (must match WebApi's AuthSettings)
var maxSessionHours = builder.Configuration.GetValue("AuthSettings:MaxSessionHours", 24);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(maxSessionHours);
        options.SlidingExpiration = false;

        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = context =>
            {
                var email = context.Principal?.Identity?.Name;
                if (email == null)
                {
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                var cache = context.HttpContext.RequestServices.GetRequiredService<TokenCacheService>();

                if (!cache.HasTokens(email))
                {
                    Console.WriteLine($"[COOKIE] No cached tokens for {email}, rejecting");
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                var tokenData = cache.Get(email);
                if (tokenData == null)
                {
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                if (tokenData.SessionAbsoluteExpiry <= DateTime.UtcNow)
                {
                    Console.WriteLine($"[COOKIE] Session expired for {email}, rejecting");
                    cache.Remove(email);
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                if (tokenData.AccessTokenExpiry <= DateTime.UtcNow)
                {
                    Console.WriteLine($"[COOKIE] Access token expired for {email}, rejecting");
                    cache.Remove(email);
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

builder.Services.AddSingleton<TokenCacheService>();
builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthStateProvider>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IApiClient, ServerApiClient>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
    app.UseWebAssemblyDebugging();
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
//  AUTH ENDPOINTS
// =====================================================================

app.MapPost("/Account/Login", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    TokenCacheService tokenCache,
    IConfiguration config,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? returnUrl = null) =>
{
    Console.WriteLine($"[LOGIN] {email}");

    var client = httpClientFactory.CreateClient("WebApi");

    // Step 1: Call Identity's /login endpoint
    var loginResponse = await client.PostAsJsonAsync("api/identity/login", new { email, password });

    if (!loginResponse.IsSuccessStatusCode)
    {
        Console.WriteLine($"[LOGIN] {email} FAILED: {loginResponse.StatusCode}");
        return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
    }

    var tokens = await loginResponse.Content.ReadFromJsonAsync<IdentityTokenResponse>();
    if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
    {
        Console.WriteLine($"[LOGIN] {email} FAILED: empty token response");
        return Results.Redirect($"/Account/Login?error=Login+failed&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
    }

    Console.WriteLine($"[LOGIN] {email} got tokens, expiresIn={tokens.ExpiresIn}s");

    // Step 2: Call /api/auth/me to get user info + roles
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
    var meResponse = await client.GetAsync("api/auth/me");
    var userInfo = meResponse.IsSuccessStatusCode
        ? await meResponse.Content.ReadFromJsonAsync<UserInfo>()
        : null;

    var roles = userInfo?.Roles ?? [];
    Console.WriteLine($"[LOGIN] {email} roles=[{string.Join(",", roles)}]");

    // Step 3: Store tokens in server-side cache
    var sessionHours = config.GetValue("AuthSettings:MaxSessionHours", 24);
    var renewalBuffer = TimeSpan.FromSeconds(tokens.ExpiresIn / 2.0);

    var tokenData = new TokenData
    {
        AccessToken = tokens.AccessToken,
        RefreshToken = tokens.RefreshToken,
        AccessTokenExpiry = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn),
        SessionAbsoluteExpiry = DateTime.UtcNow.AddHours(sessionHours),
        RenewalBuffer = renewalBuffer
    };
    tokenCache.Store(email, tokenData);

    // Step 4: Cookie stores identity claims only — NO tokens
    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, email),
        new(ClaimTypes.Email, email)
    };
    claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
        new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(sessionHours)
        });

    Console.WriteLine($"[LOGIN] {email} SUCCESS, buffer={renewalBuffer.TotalSeconds:F0}s");
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

    // Call our custom register endpoint (assigns "User" role)
    var response = await client.PostAsJsonAsync("api/auth/register",
        new RegisterRequest { Email = email, Password = password, FirstName = firstName, LastName = lastName });

    if (response.IsSuccessStatusCode)
    {
        Console.WriteLine($"[REGISTER] {email} SUCCESS");
        return Results.Redirect("/Account/Login?message=Registration+successful");
    }

    // Try to extract error details
    try
    {
        var errorBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[REGISTER] {email} FAILED: {errorBody}");

        // Try parse as our custom error format
        var errorObj = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(errorBody);
        if (errorObj.TryGetProperty("errors", out var errorsArr))
        {
            var errors = new List<string>();
            foreach (var err in errorsArr.EnumerateArray())
                errors.Add(err.GetString() ?? "Unknown error");
            return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(string.Join(", ", errors))}");
        }
    }
    catch { /* Fall through */ }

    return Results.Redirect("/Account/Register?error=Registration+failed");
});

app.MapPost("/Account/Logout", async (HttpContext context, TokenCacheService tokenCache) =>
{
    var email = context.User.Identity?.Name;
    Console.WriteLine($"[LOGOUT] {email}");

    if (email != null) tokenCache.Remove(email);

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

// =====================================================================
//  BFF PROXY ENDPOINTS (for WASM components)
// =====================================================================

app.MapGet("/api/bff/me", async (HttpContext context, IAuthService authService) =>
{
    var email = context.User.Identity?.Name;
    if (email == null) return Results.Unauthorized();

    var userInfo = await authService.GetAsync<UserInfo>("api/auth/me");
    return userInfo != null ? Results.Ok(userInfo) : Results.StatusCode(502);
}).RequireAuthorization();

app.MapGet("/api/bff/token-status", (HttpContext context, IAuthService authService) =>
{
    var email = context.User.Identity?.Name;
    if (email == null) return Results.Unauthorized();

    return Results.Ok(authService.GetTokenStatus());
}).RequireAuthorization();

app.Run();