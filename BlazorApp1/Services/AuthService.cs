using Shared.Auth;
using System.Net.Http.Headers;

namespace BlazorApp1.Services;

public interface IAuthService
{
    Task<T?> GetAsync<T>(string endpoint);
    Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data);
    TokenStatusResponse GetTokenStatus();
}

/// <summary>
/// Makes authenticated API calls to WebApi using bearer token from TokenCacheService.
/// 
/// SLIDING SESSION RULES (unchanged from Step 1b):
/// 1. Token valid + NOT in renewal window → use as-is
/// 2. Token valid + IN renewal window → call Identity's /refresh, then use new token
/// 3. Token expired → SESSION DEAD, return null
/// 4. Session absolute expiry reached → SESSION DEAD
/// </summary>
public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly TokenCacheService _tokenCache;

    public AuthService(
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        TokenCacheService tokenCache)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
        _tokenCache = tokenCache;
    }

    private string? GetCurrentUserEmail() =>
        _httpContextAccessor.HttpContext?.User?.Identity?.Name;

    private TokenData? GetTokens()
    {
        var email = GetCurrentUserEmail();
        return email != null ? _tokenCache.Get(email) : null;
    }

    public TokenStatusResponse GetTokenStatus()
    {
        var tokenData = GetTokens();
        if (tokenData == null)
            return new TokenStatusResponse { HasTokenData = false, ServerTimeUtc = DateTime.UtcNow };

        var now = DateTime.UtcNow;
        var accessLeft = (tokenData.AccessTokenExpiry - now).TotalSeconds;
        var sessionLeft = (tokenData.SessionAbsoluteExpiry - now).TotalSeconds;

        return new TokenStatusResponse
        {
            HasTokenData = true,
            ServerTimeUtc = now,
            AccessTokenExpiry = tokenData.AccessTokenExpiry,
            SessionAbsoluteExpiry = tokenData.SessionAbsoluteExpiry,
            SecondsUntilAccessExpiry = accessLeft,
            SecondsUntilSessionExpiry = sessionLeft,
            RenewalBufferSeconds = tokenData.RenewalBuffer.TotalSeconds,
            IsAccessTokenExpired = accessLeft <= 0,
            IsInRenewalWindow = accessLeft > 0 && accessLeft <= tokenData.RenewalBuffer.TotalSeconds,
            IsSessionExpired = sessionLeft <= 0
        };
    }

    public async Task<T?> GetAsync<T>(string endpoint)
    {
        Console.WriteLine($"[AUTH] GET {endpoint}");

        var client = await GetAuthenticatedClientAsync();
        if (client == null)
        {
            Console.WriteLine($"[AUTH] GET {endpoint} → no client (expired)");
            return default;
        }

        var response = await client.GetAsync(endpoint);
        Console.WriteLine($"[AUTH] GET {endpoint} → {(int)response.StatusCode}");

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            Console.WriteLine($"[AUTH] GET {endpoint} → 401, session dead");
            return default;
        }

        if (response.IsSuccessStatusCode)
            return await response.Content.ReadFromJsonAsync<T>();

        return default;
    }

    public async Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data)
    {
        Console.WriteLine($"[AUTH] POST {endpoint}");

        var client = await GetAuthenticatedClientAsync();
        if (client == null) return default;

        var response = await client.PostAsJsonAsync(endpoint, data);
        Console.WriteLine($"[AUTH] POST {endpoint} → {(int)response.StatusCode}");

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return default;

        if (response.IsSuccessStatusCode)
            return await response.Content.ReadFromJsonAsync<TResponse>();

        return default;
    }

    /// <summary>
    /// Calls Identity's /api/identity/refresh endpoint with the stored refresh token.
    /// </summary>
    private async Task<bool> TryRefreshTokenAsync()
    {
        var email = GetCurrentUserEmail();
        var tokenData = GetTokens();

        if (email == null || tokenData == null)
        {
            Console.WriteLine("[AUTH] Refresh SKIP: no user/tokens");
            return false;
        }

        if (tokenData.SessionAbsoluteExpiry <= DateTime.UtcNow)
        {
            Console.WriteLine("[AUTH] Refresh BLOCKED: session absolute expiry reached");
            _tokenCache.Remove(email);
            return false;
        }

        Console.WriteLine($"[AUTH] Refresh START for {email}");

        try
        {
            var client = _httpClientFactory.CreateClient("WebApi");

            // Call Identity's built-in /refresh endpoint
            var refreshRequest = new IdentityRefreshRequest { RefreshToken = tokenData.RefreshToken };
            var response = await client.PostAsJsonAsync("api/identity/refresh", refreshRequest);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[AUTH] Refresh FAILED: {(int)response.StatusCode} - {error}");
                return false;
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<IdentityTokenResponse>();
            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                Console.WriteLine("[AUTH] Refresh FAILED: empty response");
                return false;
            }

            // Compute new expiry and renewal buffer
            var newExpiry = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn);
            var newRenewalBuffer = TimeSpan.FromSeconds(tokenResponse.ExpiresIn / 2.0);

            var newTokenData = new TokenData
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                AccessTokenExpiry = newExpiry,
                SessionAbsoluteExpiry = tokenData.SessionAbsoluteExpiry, // preserve original
                RenewalBuffer = newRenewalBuffer
            };

            _tokenCache.Store(email, newTokenData);
            Console.WriteLine($"[AUTH] Refresh SUCCESS: new expiry {newExpiry:HH:mm:ss} UTC, buffer={newRenewalBuffer.TotalSeconds:F0}s");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AUTH] Refresh EXCEPTION: {ex.Message}");
            return false;
        }
    }

    private async Task<HttpClient?> GetAuthenticatedClientAsync()
    {
        var tokenData = GetTokens();
        if (tokenData == null)
        {
            Console.WriteLine("[AUTH] GetClient: no tokens");
            return null;
        }

        var now = DateTime.UtcNow;

        if (tokenData.SessionAbsoluteExpiry <= now)
        {
            var email = GetCurrentUserEmail();
            Console.WriteLine($"[AUTH] GetClient: SESSION EXPIRED for {email}");
            if (email != null) _tokenCache.Remove(email);
            return null;
        }

        var timeLeft = tokenData.AccessTokenExpiry - now;

        // TOKEN EXPIRED → dead
        if (timeLeft <= TimeSpan.Zero)
        {
            Console.WriteLine($"[AUTH] GetClient: TOKEN EXPIRED ({timeLeft.TotalSeconds:F0}s ago) — session dead");
            return null;
        }

        // IN RENEWAL WINDOW → refresh
        if (timeLeft <= tokenData.RenewalBuffer)
        {
            Console.WriteLine($"[AUTH] GetClient: renewal window ({timeLeft.TotalSeconds:F0}s left), refreshing...");
            if (await TryRefreshTokenAsync())
                tokenData = GetTokens();
            else
                Console.WriteLine("[AUTH] GetClient: refresh failed, using current token");
        }

        var client = _httpClientFactory.CreateClient("WebApi");
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenData!.AccessToken);
        return client;
    }
}