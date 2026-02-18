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

var maxSessionHours = builder.Configuration.GetValue("AuthSettings:MaxSessionHours", 24);

// =====================================================================
//  Authentication: main cookie + external cookie + Microsoft
// =====================================================================

var authBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
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
    })
    // Temporary cookie for external auth flow (lives only during OAuth redirect)
    .AddCookie("ExternalCookie", options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
    });

// Microsoft sign-in (optional: only enabled if config has ClientId)
var msClientId = builder.Configuration["MicrosoftAuth:ClientId"];
if (!string.IsNullOrEmpty(msClientId))
{
    authBuilder.AddMicrosoftAccount(options =>
    {
        options.SignInScheme = "ExternalCookie";
        options.ClientId = msClientId;
        options.ClientSecret = builder.Configuration["MicrosoftAuth:ClientSecret"]!;
        // /common = org + personal, /consumers = personal only, /organizations = org only
        options.AuthorizationEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
        options.TokenEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
    });
    Console.WriteLine("[STARTUP] Microsoft sign-in ENABLED");
}
else
{
    Console.WriteLine("[STARTUP] Microsoft sign-in DISABLED (no MicrosoftAuth:ClientId in config)");
}

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
//  Shared helper: store tokens + set cookie after any login flow
// =====================================================================

static async Task StoreTokensAndSignIn(
    HttpContext context,
    TokenCacheService tokenCache,
    IConfiguration config,
    IdentityTokenResponse tokens,
    string email,
    List<string> roles)
{
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

    Console.WriteLine($"[AUTH] Stored tokens + cookie for {email}, buffer={renewalBuffer.TotalSeconds:F0}s");
}

// =====================================================================
//  PASSWORD LOGIN
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

    var loginResponse = await client.PostAsJsonAsync("api/identity/login", new { email, password });
    if (!loginResponse.IsSuccessStatusCode)
    {
        Console.WriteLine($"[LOGIN] {email} FAILED: {loginResponse.StatusCode}");
        return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
    }

    var tokens = await loginResponse.Content.ReadFromJsonAsync<IdentityTokenResponse>();
    if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
        return Results.Redirect($"/Account/Login?error=Login+failed&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");

    // Get roles
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
    var meResponse = await client.GetAsync("api/auth/me");
    var userInfo = meResponse.IsSuccessStatusCode
        ? await meResponse.Content.ReadFromJsonAsync<UserInfo>()
        : null;

    await StoreTokensAndSignIn(context, tokenCache, config, tokens, email, userInfo?.Roles ?? []);

    Console.WriteLine($"[LOGIN] {email} SUCCESS");
    return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
});

// =====================================================================
//  REGISTRATION
// =====================================================================

app.MapPost("/Account/Register", async (
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? firstName,
    [FromForm] string? lastName) =>
{
    Console.WriteLine($"[REGISTER] {email}");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/register",
        new RegisterRequest { Email = email, Password = password, FirstName = firstName, LastName = lastName });

    if (response.IsSuccessStatusCode)
    {
        Console.WriteLine($"[REGISTER] {email} SUCCESS");
        return Results.Redirect("/Account/Login?message=Registration+successful");
    }

    try
    {
        var errorBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[REGISTER] {email} FAILED: {errorBody}");
        var errorObj = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(errorBody);
        if (errorObj.TryGetProperty("errors", out var errorsArr))
        {
            var errors = new List<string>();
            foreach (var err in errorsArr.EnumerateArray())
                errors.Add(err.GetString() ?? "Unknown error");
            return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(string.Join(", ", errors))}");
        }
    }
    catch { }

    return Results.Redirect("/Account/Register?error=Registration+failed");
});

// =====================================================================
//  EXTERNAL LOGIN (Microsoft)
// =====================================================================

app.MapGet("/Account/ExternalLogin", (string provider, string? returnUrl, HttpContext context) =>
{
    Console.WriteLine($"[EXTERNAL-LOGIN] Challenge for {provider}");

    var properties = new AuthenticationProperties
    {
        RedirectUri = $"/Account/ExternalLoginCallback?returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}"
    };
    properties.Items["LoginProvider"] = provider;

    return TypedResults.Challenge(properties, [provider]);
});

app.MapGet("/Account/ExternalLoginCallback", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    TokenCacheService tokenCache,
    IConfiguration config,
    string? returnUrl = null) =>
{
    Console.WriteLine("[EXTERNAL-CALLBACK] Processing...");

    // Step 1: Read the external cookie (set by Microsoft auth middleware)
    var result = await context.AuthenticateAsync("ExternalCookie");
    if (!result.Succeeded || result.Principal == null)
    {
        Console.WriteLine("[EXTERNAL-CALLBACK] FAILED: no external principal");
        return Results.Redirect("/Account/Login?error=External+login+failed");
    }

    // Step 2: Extract claims from Microsoft identity
    var providerUserId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
    var email = result.Principal.FindFirstValue(ClaimTypes.Email) ?? "";
    var firstName = result.Principal.FindFirstValue(ClaimTypes.GivenName);
    var lastName = result.Principal.FindFirstValue(ClaimTypes.Surname);
    var provider = result.Properties?.Items["LoginProvider"] ?? "Microsoft";

    Console.WriteLine($"[EXTERNAL-CALLBACK] {provider}: {email} (id={providerUserId})");

    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(providerUserId))
    {
        Console.WriteLine("[EXTERNAL-CALLBACK] FAILED: missing email or provider ID");
        return Results.Redirect("/Account/Login?error=Could+not+get+email+from+Microsoft");
    }

    // Step 3: Call WebApi to create/link user and get bearer tokens
    var client = httpClientFactory.CreateClient("WebApi");
    var externalResponse = await client.PostAsJsonAsync("api/auth/external-login", new ExternalLoginRequest
    {
        Provider = provider,
        ProviderUserId = providerUserId,
        Email = email,
        FirstName = firstName,
        LastName = lastName
    });

    if (!externalResponse.IsSuccessStatusCode)
    {
        var error = await externalResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"[EXTERNAL-CALLBACK] WebApi FAILED: {error}");
        return Results.Redirect("/Account/Login?error=External+login+failed");
    }

    var tokens = await externalResponse.Content.ReadFromJsonAsync<IdentityTokenResponse>();
    if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
    {
        Console.WriteLine("[EXTERNAL-CALLBACK] FAILED: empty token response");
        return Results.Redirect("/Account/Login?error=External+login+failed");
    }

    // Step 4: Get roles from /api/auth/me
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
    var meResponse = await client.GetAsync("api/auth/me");
    var userInfo = meResponse.IsSuccessStatusCode
        ? await meResponse.Content.ReadFromJsonAsync<UserInfo>()
        : null;

    // Step 5: Store tokens + sign in with main cookie
    await StoreTokensAndSignIn(context, tokenCache, config, tokens, email, userInfo?.Roles ?? []);

    // Step 6: Clean up external cookie
    await context.SignOutAsync("ExternalCookie");

    Console.WriteLine($"[EXTERNAL-CALLBACK] {email} SUCCESS via {provider}");
    return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
});

// =====================================================================
//  LOGOUT
// =====================================================================

app.MapPost("/Account/Logout", async (HttpContext context, TokenCacheService tokenCache) =>
{
    var email = context.User.Identity?.Name;
    Console.WriteLine($"[LOGOUT] {email}");

    if (email != null) tokenCache.Remove(email);

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

// =====================================================================
//  BFF PROXY ENDPOINTS
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
    // No .RequireAuthorization() — must return JSON even when cookie is rejected,
    // otherwise the cookie middleware returns 302 → WASM HttpClient follows redirect
    // → gets 200 HTML → JSON parse fails → auth state never updates.
    if (context.User.Identity?.IsAuthenticated != true)
    {
        return Results.Ok(new TokenStatusResponse
        {
            HasTokenData = false,
            ServerTimeUtc = DateTime.UtcNow
        });
    }

    return Results.Ok(authService.GetTokenStatus());
});
// ↑ NO .RequireAuthorization() here

app.Run();