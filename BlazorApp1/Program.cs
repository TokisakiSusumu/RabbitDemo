using BlazorApp1.Components;
using BlazorApp1.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shared.Auth;
using System.Security.Claims;
using System.Text.Json;

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
        options.ExpireTimeSpan = TimeSpan.FromDays(7);  // Match refresh token lifetime
        options.SlidingExpiration = true;

        // Cookie events for debugging
        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = async context =>
            {
                Console.WriteLine($"");
                Console.WriteLine($"▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: START");
                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: Current UTC = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");

                var userName = context.Principal?.Identity?.Name;
                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: User = {userName}");

                // Check token data
                var tokenDataClaim = context.Principal?.FindFirst("TokenData");
                if (tokenDataClaim != null)
                {
                    try
                    {
                        var tokenData = JsonSerializer.Deserialize<TokenData>(tokenDataClaim.Value);
                        if (tokenData != null)
                        {
                            Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: Token data found:");
                            Console.WriteLine($">>>   - AccessToken expires: {tokenData.AccessTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");
                            Console.WriteLine($">>>   - RefreshToken expires: {tokenData.RefreshTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");

                            var accessTimeLeft = tokenData.AccessTokenExpiry - DateTime.UtcNow;
                            var refreshTimeLeft = tokenData.RefreshTokenExpiry - DateTime.UtcNow;

                            Console.WriteLine($">>>   - Time until access expiry: {accessTimeLeft.TotalSeconds:F0} seconds");
                            Console.WriteLine($">>>   - Time until refresh expiry: {refreshTimeLeft.TotalDays:F2} days");

                            // If access token is expired, check refresh token
                            if (tokenData.AccessTokenExpiry <= DateTime.UtcNow)
                            {
                                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: ⚠️ Access token is EXPIRED!");

                                // If refresh token is also expired, reject the cookie
                                if (tokenData.RefreshTokenExpiry <= DateTime.UtcNow)
                                {
                                    Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: ❌ Refresh token also EXPIRED!");
                                    Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: REJECTING principal - user must re-login");
                                    context.RejectPrincipal();
                                    await context.HttpContext.SignOutAsync();
                                    return;
                                }

                                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: ✓ Refresh token still valid");
                                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: AuthService will refresh on next API call");
                            }
                            else
                            {
                                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: ✓ Access token is still valid");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: ERROR parsing token data - {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: No TokenData claim found in cookie");
                }

                Console.WriteLine($">>> [BLAZOR] Cookie.OnValidatePrincipal: END - Principal validated");
                Console.WriteLine($"");
            },
            OnSigningIn = context =>
            {
                Console.WriteLine($"");
                Console.WriteLine($">>> [BLAZOR] Cookie.OnSigningIn: User signing in...");
                Console.WriteLine($">>>   - User: {context.Principal?.Identity?.Name}");
                Console.WriteLine($">>>   - Claims count: {context.Principal?.Claims.Count()}");
                Console.WriteLine($"");
                return Task.CompletedTask;
            },
            OnSignedIn = context =>
            {
                Console.WriteLine($"");
                Console.WriteLine($">>> [BLAZOR] Cookie.OnSignedIn: ✅ User signed in successfully");
                Console.WriteLine($">>>   - User: {context.Principal?.Identity?.Name}");
                Console.WriteLine($"");
                return Task.CompletedTask;
            },
            OnSigningOut = context =>
            {
                Console.WriteLine($"");
                Console.WriteLine($">>> [BLAZOR] Cookie.OnSigningOut: User signing out...");
                Console.WriteLine($"");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// Register services
builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthStateProvider>();
builder.Services.AddScoped<IAuthService, AuthService>();

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

// ===== Authentication Endpoints =====

app.MapPost("/Account/Login", async (
    HttpContext context,
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? returnUrl = null) =>
{
    Console.WriteLine($"");
    Console.WriteLine($"████████████████████████████████████████████████████████████████");
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: START");
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: Email = {email}");
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: Current UTC = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
    Console.WriteLine($"████████████████████████████████████████████████████████████████");

    var client = httpClientFactory.CreateClient("WebApi");
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: Calling WebApi /api/auth/login...");

    var response = await client.PostAsJsonAsync("api/auth/login", new { email, password });
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: WebApi response status = {(int)response.StatusCode} {response.StatusCode}");

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true && result.Token != null && result.RefreshToken != null)
        {
            Console.WriteLine($">>> [BLAZOR] POST /Account/Login: WebApi returned SUCCESS");
            Console.WriteLine($">>>   - AccessToken length: {result.Token.Length}");
            Console.WriteLine($">>>   - RefreshToken length: {result.RefreshToken.Length}");
            Console.WriteLine($">>>   - AccessToken expires: {result.Expiration:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($">>>   - Roles: [{string.Join(", ", result.Roles)}]");

            // Build claims including token data
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, result.Email!),
                new(ClaimTypes.Email, result.Email!)
            };
            claims.AddRange(result.Roles.Select(r => new Claim(ClaimTypes.Role, r)));

            // Store tokens in a claim (encrypted by cookie)
            var tokenData = new TokenData
            {
                AccessToken = result.Token,
                RefreshToken = result.RefreshToken,
                AccessTokenExpiry = result.Expiration ?? DateTime.UtcNow.AddMinutes(1),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
            };
            claims.Add(new Claim("TokenData", JsonSerializer.Serialize(tokenData)));

            Console.WriteLine($">>> [BLAZOR] POST /Account/Login: Creating authentication cookie...");
            Console.WriteLine($">>>   - TokenData stored with AccessExpiry = {tokenData.AccessTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");

            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                });

            Console.WriteLine($">>> [BLAZOR] POST /Account/Login: Cookie created, redirecting to {returnUrl ?? "/"}");
            Console.WriteLine($"████████████████████████████████████████████████████████████████");
            Console.WriteLine($"");

            return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
        }
    }

    var errorContent = await response.Content.ReadAsStringAsync();
    Console.WriteLine($">>> [BLAZOR] POST /Account/Login: FAILED");
    Console.WriteLine($">>>   - Response: {errorContent}");
    Console.WriteLine($"████████████████████████████████████████████████████████████████");
    Console.WriteLine($"");

    return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
});

app.MapPost("/Account/Register", async (
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? firstName,
    [FromForm] string? lastName) =>
{
    Console.WriteLine($">>> [BLAZOR] POST /Account/Register: Registering {email}");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/register", new { email, password, firstName, lastName });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true)
        {
            Console.WriteLine($">>> [BLAZOR] POST /Account/Register: SUCCESS");
            return Results.Redirect("/Account/Login?message=Registration+successful");
        }

        var errors = string.Join(", ", result?.Errors ?? ["Registration failed"]);
        return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(errors)}");
    }

    Console.WriteLine($">>> [BLAZOR] POST /Account/Register: FAILED");
    return Results.Redirect("/Account/Register?error=Registration+failed");
});

app.MapPost("/Account/Logout", async (HttpContext context, IHttpClientFactory httpClientFactory) =>
{
    Console.WriteLine($"");
    Console.WriteLine($">>> [BLAZOR] POST /Account/Logout: START");

    // Try to revoke refresh tokens on the backend
    var tokenDataClaim = context.User.FindFirst("TokenData");
    if (tokenDataClaim != null)
    {
        try
        {
            var tokenData = JsonSerializer.Deserialize<TokenData>(tokenDataClaim.Value);
            if (tokenData != null)
            {
                Console.WriteLine($">>> [BLAZOR] POST /Account/Logout: Revoking tokens on WebApi...");
                var client = httpClientFactory.CreateClient("WebApi");
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenData.AccessToken);

                // Fire and forget - don't block logout if this fails
                _ = client.PostAsync("api/auth/logout", null);
            }
        }
        catch
        {
            // Ignore errors during logout cleanup
        }
    }

    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    Console.WriteLine($">>> [BLAZOR] POST /Account/Logout: Cookie cleared, redirecting");
    Console.WriteLine($"");

    return Results.Redirect("/");
});

app.Run();