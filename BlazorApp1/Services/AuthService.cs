using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Shared.Auth;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorApp1.Services;

public interface IAuthService
{
    Task<T?> GetAsync<T>(string endpoint);
    Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data);
    Task<bool> IsTokenExpiringSoonAsync();
    Task<bool> RefreshTokenIfNeededAsync();
    TokenStatus GetTokenStatus();
}

/// <summary>
/// Token status for debugging
/// </summary>
public class TokenStatus
{
    public bool HasTokenData { get; set; }
    public DateTime? AccessTokenExpiry { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }
    public bool IsAccessTokenExpired { get; set; }
    public bool IsAccessTokenExpiringSoon { get; set; }
    public bool IsRefreshTokenExpired { get; set; }
    public TimeSpan? TimeUntilAccessExpiry { get; set; }
    public TimeSpan? TimeUntilRefreshExpiry { get; set; }
}

/// <summary>
/// Service for making authenticated API calls to WebApi.
/// Automatically handles token refresh when needed.
/// </summary>
public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthService> _logger;

    // Buffer time before token expiry to trigger refresh (30 seconds for testing, normally 5 minutes)
    private static readonly TimeSpan TokenRefreshBuffer = TimeSpan.FromSeconds(30);

    public AuthService(
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;

        Console.WriteLine($">>> [BLAZOR] AuthService: Initialized with RefreshBuffer={TokenRefreshBuffer.TotalSeconds} seconds");
    }

    public TokenStatus GetTokenStatus()
    {
        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
        {
            return new TokenStatus { HasTokenData = false };
        }

        var now = DateTime.UtcNow;
        var timeUntilAccessExpiry = tokenData.AccessTokenExpiry - now;
        var timeUntilRefreshExpiry = tokenData.RefreshTokenExpiry - now;

        return new TokenStatus
        {
            HasTokenData = true,
            AccessTokenExpiry = tokenData.AccessTokenExpiry,
            RefreshTokenExpiry = tokenData.RefreshTokenExpiry,
            IsAccessTokenExpired = tokenData.AccessTokenExpiry <= now,
            IsAccessTokenExpiringSoon = timeUntilAccessExpiry <= TokenRefreshBuffer,
            IsRefreshTokenExpired = tokenData.RefreshTokenExpiry <= now,
            TimeUntilAccessExpiry = timeUntilAccessExpiry,
            TimeUntilRefreshExpiry = timeUntilRefreshExpiry
        };
    }

    public async Task<T?> GetAsync<T>(string endpoint)
    {
        Console.WriteLine($"");
        Console.WriteLine($"──────────────────────────────────────────────────────────────");
        Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: START");
        Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Endpoint = {endpoint}");
        Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"──────────────────────────────────────────────────────────────");

        var client = await GetAuthenticatedClientAsync();
        if (client == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: FAILED - No authenticated client available");
            return default;
        }

        try
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Making HTTP GET request...");
            var response = await client.GetAsync(endpoint);
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Response status = {(int)response.StatusCode} {response.StatusCode}");

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Got 401 - Token may be expired, attempting refresh...");

                // Try to refresh token and retry
                if (await RefreshTokenIfNeededAsync())
                {
                    Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Refresh successful, retrying request...");
                    client = await GetAuthenticatedClientAsync();
                    if (client != null)
                    {
                        response = await client.GetAsync(endpoint);
                        Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Retry response status = {(int)response.StatusCode} {response.StatusCode}");
                    }
                }
                else
                {
                    Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: Refresh FAILED - User needs to re-login");
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<T>();
                Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: SUCCESS - Data retrieved");
                return result;
            }

            Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: FAILED - Status {response.StatusCode}");
            return default;
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAsync: EXCEPTION - {ex.Message}");
            return default;
        }
    }

    public async Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data)
    {
        Console.WriteLine($"");
        Console.WriteLine($"──────────────────────────────────────────────────────────────");
        Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: START");
        Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Endpoint = {endpoint}");
        Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"──────────────────────────────────────────────────────────────");

        var client = await GetAuthenticatedClientAsync();
        if (client == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: FAILED - No authenticated client available");
            return default;
        }

        try
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Making HTTP POST request...");
            var response = await client.PostAsJsonAsync(endpoint, data);
            Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Response status = {(int)response.StatusCode} {response.StatusCode}");

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Got 401 - Attempting token refresh...");

                if (await RefreshTokenIfNeededAsync())
                {
                    Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Refresh successful, retrying request...");
                    client = await GetAuthenticatedClientAsync();
                    if (client != null)
                    {
                        response = await client.PostAsJsonAsync(endpoint, data);
                        Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: Retry response status = {(int)response.StatusCode} {response.StatusCode}");
                    }
                }
            }

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<TResponse>();
                Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: SUCCESS");
                return result;
            }

            Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: FAILED - Status {response.StatusCode}");
            return default;
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.PostAsync: EXCEPTION - {ex.Message}");
            return default;
        }
    }

    public async Task<bool> IsTokenExpiringSoonAsync()
    {
        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.IsTokenExpiringSoon: No token data");
            return false;
        }

        var timeUntilExpiry = tokenData.AccessTokenExpiry - DateTime.UtcNow;
        var isExpiringSoon = timeUntilExpiry <= TokenRefreshBuffer;

        Console.WriteLine($">>> [BLAZOR] AuthService.IsTokenExpiringSoon: Time until expiry = {timeUntilExpiry.TotalSeconds:F0} seconds, ExpiringSoon = {isExpiringSoon}");

        return isExpiringSoon;
    }

    public async Task<bool> RefreshTokenIfNeededAsync()
    {
        Console.WriteLine($"");
        Console.WriteLine($"╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine($"║ [BLAZOR] AuthService.RefreshTokenIfNeededAsync: START        ║");
        Console.WriteLine($"╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine($">>> [BLAZOR] Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");

        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: FAILED - No HttpContext");
            return false;
        }

        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: FAILED - No token data in cookie");
            return false;
        }

        Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: Token data found:");
        Console.WriteLine($">>>   - AccessToken expires: {tokenData.AccessTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - RefreshToken expires: {tokenData.RefreshTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - Time until access expiry: {(tokenData.AccessTokenExpiry - DateTime.UtcNow).TotalSeconds:F0} seconds");
        Console.WriteLine($">>>   - Time until refresh expiry: {(tokenData.RefreshTokenExpiry - DateTime.UtcNow).TotalDays:F2} days");

        // Check if refresh token itself is expired
        if (tokenData.RefreshTokenExpiry <= DateTime.UtcNow)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: FAILED - RefreshToken is expired! User must re-login.");
            return false;
        }

        Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: Calling WebApi /api/auth/refresh...");

        try
        {
            var client = _httpClientFactory.CreateClient("WebApi");
            var refreshRequest = new RefreshTokenRequest
            {
                Token = tokenData.AccessToken,
                RefreshToken = tokenData.RefreshToken
            };

            var response = await client.PostAsJsonAsync("api/auth/refresh", refreshRequest);
            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: Response status = {(int)response.StatusCode} {response.StatusCode}");

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: FAILED - {errorContent}");
                return false;
            }

            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            if (authResponse?.Success != true)
            {
                Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: FAILED - API returned Success=false");
                return false;
            }

            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: New tokens received:");
            Console.WriteLine($">>>   - New AccessToken expires: {authResponse.Expiration:yyyy-MM-dd HH:mm:ss} UTC");

            // Update the cookie with new tokens
            await UpdateAuthCookieAsync(httpContext, authResponse);

            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: Cookie updated with new tokens");
            Console.WriteLine($"╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine($"║ [BLAZOR] AuthService.RefreshTokenIfNeededAsync: SUCCESS!     ║");
            Console.WriteLine($"╚══════════════════════════════════════════════════════════════╝");
            Console.WriteLine($"");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.RefreshTokenIfNeededAsync: EXCEPTION - {ex.Message}");
            return false;
        }
    }

    private async Task<HttpClient?> GetAuthenticatedClientAsync()
    {
        Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Getting authenticated client...");

        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: No token data in cookie");
            return null;
        }

        Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Token found, checking expiry...");
        Console.WriteLine($">>>   - AccessToken expires: {tokenData.AccessTokenExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - Current time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - Time until expiry: {(tokenData.AccessTokenExpiry - DateTime.UtcNow).TotalSeconds:F0} seconds");

        // Check if we should refresh before making the call
        if (await IsTokenExpiringSoonAsync())
        {
            Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Token expiring soon, refreshing first...");
            var refreshed = await RefreshTokenIfNeededAsync();

            if (refreshed)
            {
                tokenData = GetTokenDataFromCookie();  // Get updated token
                if (tokenData == null)
                {
                    Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Token data lost after refresh!");
                    return null;
                }
                Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Using refreshed token");
            }
            else
            {
                Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Refresh failed, using existing token (may fail)");
            }
        }

        var client = _httpClientFactory.CreateClient("WebApi");
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenData.AccessToken);

        Console.WriteLine($">>> [BLAZOR] AuthService.GetAuthenticatedClientAsync: Client ready with Bearer token");
        return client;
    }

    private TokenData? GetTokenDataFromCookie()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        var tokenDataJson = httpContext.User.FindFirstValue("TokenData");
        if (string.IsNullOrEmpty(tokenDataJson))
            return null;

        try
        {
            return JsonSerializer.Deserialize<TokenData>(tokenDataJson);
        }
        catch
        {
            return null;
        }
    }

    private async Task UpdateAuthCookieAsync(HttpContext httpContext, AuthResponse authResponse)
    {
        Console.WriteLine($">>> [BLAZOR] AuthService.UpdateAuthCookieAsync: Updating cookie with new tokens...");

        // Preserve existing claims but update token data
        var existingClaims = httpContext.User.Claims
            .Where(c => c.Type != "TokenData")
            .ToList();

        var tokenData = new TokenData
        {
            AccessToken = authResponse.Token!,
            RefreshToken = authResponse.RefreshToken!,
            AccessTokenExpiry = authResponse.Expiration ?? DateTime.UtcNow.AddMinutes(1),
            RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
        };

        var newClaims = new List<Claim>(existingClaims)
        {
            new("TokenData", JsonSerializer.Serialize(tokenData))
        };

        await httpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(newClaims, CookieAuthenticationDefaults.AuthenticationScheme)),
            new AuthenticationProperties { IsPersistent = true });

        Console.WriteLine($">>> [BLAZOR] AuthService.UpdateAuthCookieAsync: Cookie updated successfully");
    }
}