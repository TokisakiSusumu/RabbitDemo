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

    // Buffer time before token expiry to trigger refresh (5 minutes)
    private static readonly TimeSpan TokenRefreshBuffer = TimeSpan.FromMinutes(5);

    public AuthService(
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<T?> GetAsync<T>(string endpoint)
    {
        var client = await GetAuthenticatedClientAsync();
        if (client == null)
        {
            _logger.LogWarning(">>> [SERVER] AuthService: No authenticated client available");
            return default;
        }

        try
        {
            var response = await client.GetAsync(endpoint);

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning(">>> [SERVER] AuthService: 401 Unauthorized - token may be expired");

                // Try to refresh token and retry
                if (await RefreshTokenIfNeededAsync())
                {
                    client = await GetAuthenticatedClientAsync();
                    if (client != null)
                    {
                        response = await client.GetAsync(endpoint);
                    }
                }
            }

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<T>();
            }

            _logger.LogError(">>> [SERVER] AuthService: API call failed with status {StatusCode}", response.StatusCode);
            return default;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ">>> [SERVER] AuthService: Exception during API call");
            return default;
        }
    }

    public async Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data)
    {
        var client = await GetAuthenticatedClientAsync();
        if (client == null)
        {
            _logger.LogWarning(">>> [SERVER] AuthService: No authenticated client available");
            return default;
        }

        try
        {
            var response = await client.PostAsJsonAsync(endpoint, data);

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning(">>> [SERVER] AuthService: 401 Unauthorized - attempting token refresh");

                if (await RefreshTokenIfNeededAsync())
                {
                    client = await GetAuthenticatedClientAsync();
                    if (client != null)
                    {
                        response = await client.PostAsJsonAsync(endpoint, data);
                    }
                }
            }

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<TResponse>();
            }

            _logger.LogError(">>> [SERVER] AuthService: POST failed with status {StatusCode}", response.StatusCode);
            return default;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ">>> [SERVER] AuthService: Exception during POST");
            return default;
        }
    }

    public async Task<bool> IsTokenExpiringSoonAsync()
    {
        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
            return false;

        var timeUntilExpiry = tokenData.AccessTokenExpiry - DateTime.UtcNow;
        return timeUntilExpiry <= TokenRefreshBuffer;
    }

    public async Task<bool> RefreshTokenIfNeededAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            _logger.LogWarning(">>> [SERVER] AuthService: No HttpContext available");
            return false;
        }

        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
        {
            _logger.LogWarning(">>> [SERVER] AuthService: No token data in cookie");
            return false;
        }

        // Check if refresh token itself is expired
        if (tokenData.RefreshTokenExpiry <= DateTime.UtcNow)
        {
            _logger.LogWarning(">>> [SERVER] AuthService: Refresh token is expired - user must re-login");
            return false;
        }

        _logger.LogInformation(">>> [SERVER] AuthService: Attempting token refresh");

        try
        {
            var client = _httpClientFactory.CreateClient("WebApi");
            var refreshRequest = new RefreshTokenRequest
            {
                Token = tokenData.AccessToken,
                RefreshToken = tokenData.RefreshToken
            };

            var response = await client.PostAsJsonAsync("api/auth/refresh", refreshRequest);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(">>> [SERVER] AuthService: Token refresh failed");
                return false;
            }

            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            if (authResponse?.Success != true)
            {
                _logger.LogWarning(">>> [SERVER] AuthService: Token refresh returned unsuccessful response");
                return false;
            }

            // Update the cookie with new tokens
            await UpdateAuthCookieAsync(httpContext, authResponse);

            _logger.LogInformation(">>> [SERVER] AuthService: Token refresh successful");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ">>> [SERVER] AuthService: Exception during token refresh");
            return false;
        }
    }

    private async Task<HttpClient?> GetAuthenticatedClientAsync()
    {
        var tokenData = GetTokenDataFromCookie();
        if (tokenData == null)
            return null;

        // Check if we should refresh before making the call
        if (await IsTokenExpiringSoonAsync())
        {
            await RefreshTokenIfNeededAsync();
            tokenData = GetTokenDataFromCookie();  // Get updated token
            if (tokenData == null)
                return null;
        }

        var client = _httpClientFactory.CreateClient("WebApi");
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenData.AccessToken);

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
        // Preserve existing claims but update token data
        var existingClaims = httpContext.User.Claims
            .Where(c => c.Type != "TokenData")
            .ToList();

        var tokenData = new TokenData
        {
            AccessToken = authResponse.Token!,
            RefreshToken = authResponse.RefreshToken!,
            AccessTokenExpiry = authResponse.Expiration ?? DateTime.UtcNow.AddMinutes(15),
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
    }
}