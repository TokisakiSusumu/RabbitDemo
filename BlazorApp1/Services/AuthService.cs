using Shared.Auth;
using System.Net.Http.Headers;

namespace BlazorApp1.Services;

public interface IAuthService
{
    Task<T?> GetAsync<T>(string endpoint);
    Task<TResponse?> PostAsync<TRequest, TResponse>(string endpoint, TRequest data);
    Task<bool> RefreshTokenAsync();
    TokenStatus GetTokenStatus();
}

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
/// Makes authenticated API calls to WebApi using JWT from TokenCacheService.
/// 
/// KEY CHANGE: Tokens are stored in server-side memory (TokenCacheService),
/// NOT in the cookie. This means refresh works during SignalR connections.
/// </summary>
public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly TokenCacheService _tokenCache;

    // Refresh when token has less than this remaining
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(30);

    public AuthService(
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        TokenCacheService tokenCache)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
        _tokenCache = tokenCache;
    }

    private string? GetCurrentUserEmail()
    {
        return _httpContextAccessor.HttpContext?.User?.Identity?.Name;
    }

    private TokenData? GetTokens()
    {
        var email = GetCurrentUserEmail();
        return email != null ? _tokenCache.Get(email) : null;
    }

    public TokenStatus GetTokenStatus()
    {
        var tokenData = GetTokens();
        if (tokenData == null)
            return new TokenStatus { HasTokenData = false };

        var now = DateTime.UtcNow;
        return new TokenStatus
        {
            HasTokenData = true,
            AccessTokenExpiry = tokenData.AccessTokenExpiry,
            RefreshTokenExpiry = tokenData.RefreshTokenExpiry,
            IsAccessTokenExpired = tokenData.AccessTokenExpiry <= now,
            IsAccessTokenExpiringSoon = (tokenData.AccessTokenExpiry - now) <= RefreshBuffer,
            IsRefreshTokenExpired = tokenData.RefreshTokenExpiry <= now,
            TimeUntilAccessExpiry = tokenData.AccessTokenExpiry - now,
            TimeUntilRefreshExpiry = tokenData.RefreshTokenExpiry - now
        };
    }

    public async Task<T?> GetAsync<T>(string endpoint)
    {
        Console.WriteLine($"[AUTH] GET {endpoint}");

        var client = await GetAuthenticatedClientAsync();
        if (client == null) return default;

        var response = await client.GetAsync(endpoint);
        Console.WriteLine($"[AUTH] GET {endpoint} → {(int)response.StatusCode}");

        // If 401, try refresh then retry once
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            Console.WriteLine($"[AUTH] GET {endpoint} → 401, attempting refresh...");
            if (await RefreshTokenAsync())
            {
                client = await GetAuthenticatedClientAsync();
                if (client != null)
                {
                    response = await client.GetAsync(endpoint);
                    Console.WriteLine($"[AUTH] GET {endpoint} retry → {(int)response.StatusCode}");
                }
            }
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
        {
            Console.WriteLine($"[AUTH] POST {endpoint} → 401, attempting refresh...");
            if (await RefreshTokenAsync())
            {
                client = await GetAuthenticatedClientAsync();
                if (client != null)
                {
                    response = await client.PostAsJsonAsync(endpoint, data);
                    Console.WriteLine($"[AUTH] POST {endpoint} retry → {(int)response.StatusCode}");
                }
            }
        }

        if (response.IsSuccessStatusCode)
            return await response.Content.ReadFromJsonAsync<TResponse>();

        return default;
    }

    public async Task<bool> RefreshTokenAsync()
    {
        var email = GetCurrentUserEmail();
        var tokenData = GetTokens();

        if (email == null || tokenData == null)
        {
            Console.WriteLine($"[AUTH] Refresh SKIP - no user/tokens");
            return false;
        }

        if (tokenData.RefreshTokenExpiry <= DateTime.UtcNow)
        {
            Console.WriteLine($"[AUTH] Refresh FAILED - refresh token expired, must re-login");
            return false;
        }

        Console.WriteLine($"[AUTH] Refresh START for {email}");

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
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[AUTH] Refresh FAILED - {(int)response.StatusCode}: {error}");
                return false;
            }

            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            if (authResponse?.Success != true || authResponse.Token == null || authResponse.RefreshToken == null)
            {
                Console.WriteLine($"[AUTH] Refresh FAILED - API returned success=false");
                return false;
            }

            // Store new tokens in MEMORY CACHE (not cookie!)
            var newTokenData = new TokenData
            {
                AccessToken = authResponse.Token,
                RefreshToken = authResponse.RefreshToken,
                AccessTokenExpiry = authResponse.Expiration ?? DateTime.UtcNow.AddMinutes(1),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
            };

            _tokenCache.Store(email, newTokenData);
            Console.WriteLine($"[AUTH] Refresh SUCCESS - new access expires {newTokenData.AccessTokenExpiry:HH:mm:ss} UTC");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AUTH] Refresh EXCEPTION - {ex.Message}");
            return false;
        }
    }

    private async Task<HttpClient?> GetAuthenticatedClientAsync()
    {
        var tokenData = GetTokens();
        if (tokenData == null)
        {
            Console.WriteLine($"[AUTH] No tokens available");
            return null;
        }

        // Proactive refresh if expiring soon
        var timeLeft = tokenData.AccessTokenExpiry - DateTime.UtcNow;
        if (timeLeft <= RefreshBuffer && timeLeft > TimeSpan.Zero)
        {
            Console.WriteLine($"[AUTH] Token expiring in {timeLeft.TotalSeconds:F0}s, proactive refresh...");
            if (await RefreshTokenAsync())
                tokenData = GetTokens();
        }

        var client = _httpClientFactory.CreateClient("WebApi");
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenData!.AccessToken);
        return client;
    }
}
