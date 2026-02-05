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
                Console.WriteLine(">>> [SERVER] Cookie: Validating principal");

                // Check if we need to refresh the token
                var tokenDataClaim = context.Principal?.FindFirst("TokenData");
                if (tokenDataClaim != null)
                {
                    try
                    {
                        var tokenData = JsonSerializer.Deserialize<TokenData>(tokenDataClaim.Value);
                        if (tokenData != null)
                        {
                            // If access token is expired, check refresh token
                            if (tokenData.AccessTokenExpiry <= DateTime.UtcNow)
                            {
                                Console.WriteLine(">>> [SERVER] Cookie: Access token expired");

                                // If refresh token is also expired, reject the cookie
                                if (tokenData.RefreshTokenExpiry <= DateTime.UtcNow)
                                {
                                    Console.WriteLine(">>> [SERVER] Cookie: Refresh token also expired - rejecting");
                                    context.RejectPrincipal();
                                    await context.HttpContext.SignOutAsync();
                                    return;
                                }

                                // Token needs refresh - let the AuthService handle it on next API call
                                Console.WriteLine(">>> [SERVER] Cookie: Refresh token still valid - will refresh on API call");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($">>> [SERVER] Cookie: Error parsing token data - {ex.Message}");
                    }
                }
            },
            OnSigningIn = context =>
            {
                Console.WriteLine(">>> [SERVER] Cookie: Signing in user");
                return Task.CompletedTask;
            },
            OnSignedIn = context =>
            {
                Console.WriteLine($">>> [SERVER] Cookie: User signed in - {context.Principal?.Identity?.Name}");
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
    Console.WriteLine($">>> [SERVER] Login endpoint: Attempting login for {email}");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/login", new { email, password });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true && result.Token != null && result.RefreshToken != null)
        {
            Console.WriteLine($">>> [SERVER] Login endpoint: WebApi returned success");

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
                AccessTokenExpiry = result.Expiration ?? DateTime.UtcNow.AddMinutes(15),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
            };
            claims.Add(new Claim("TokenData", JsonSerializer.Serialize(tokenData)));

            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)  // Match refresh token
                });

            Console.WriteLine($">>> [SERVER] Login endpoint: Cookie created, redirecting");
            return Results.Redirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl ?? "/");
        }
    }

    Console.WriteLine($">>> [SERVER] Login endpoint: Login failed");
    return Results.Redirect($"/Account/Login?error=Invalid+credentials&returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}");
});

app.MapPost("/Account/Register", async (
    IHttpClientFactory httpClientFactory,
    [FromForm] string email,
    [FromForm] string password,
    [FromForm] string? firstName,
    [FromForm] string? lastName) =>
{
    Console.WriteLine($">>> [SERVER] Register endpoint: Attempting registration for {email}");

    var client = httpClientFactory.CreateClient("WebApi");
    var response = await client.PostAsJsonAsync("api/auth/register", new { email, password, firstName, lastName });

    if (response.IsSuccessStatusCode)
    {
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        if (result?.Success == true)
        {
            Console.WriteLine($">>> [SERVER] Register endpoint: Success");
            return Results.Redirect("/Account/Login?message=Registration+successful");
        }

        var errors = string.Join(", ", result?.Errors ?? ["Registration failed"]);
        return Results.Redirect($"/Account/Register?error={Uri.EscapeDataString(errors)}");
    }

    Console.WriteLine($">>> [SERVER] Register endpoint: Failed");
    return Results.Redirect("/Account/Register?error=Registration+failed");
});

app.MapPost("/Account/Logout", async (HttpContext context, IHttpClientFactory httpClientFactory) =>
{
    Console.WriteLine($">>> [SERVER] Logout endpoint: Logging out user");

    // Try to revoke refresh tokens on the backend
    var tokenDataClaim = context.User.FindFirst("TokenData");
    if (tokenDataClaim != null)
    {
        try
        {
            var tokenData = JsonSerializer.Deserialize<TokenData>(tokenDataClaim.Value);
            if (tokenData != null)
            {
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
    return Results.Redirect("/");
});

app.Run();