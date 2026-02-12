namespace Shared.Auth;

// ===== Custom DTOs (for our custom endpoints) =====

public record RegisterRequest
{
    public string Email { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
}

public record UserInfo
{
    public string Email { get; init; } = string.Empty;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public List<string> Roles { get; init; } = [];
}

// ===== Identity API response DTOs =====

/// <summary>
/// Response from MapIdentityApi /login and /refresh endpoints.
/// Format: { "tokenType":"Bearer", "accessToken":"...", "expiresIn":30, "refreshToken":"..." }
/// </summary>
public record IdentityTokenResponse
{
    public string TokenType { get; init; } = string.Empty;
    public string AccessToken { get; init; } = string.Empty;
    public long ExpiresIn { get; init; }
    public string RefreshToken { get; init; } = string.Empty;
}

/// <summary>
/// Request for Identity's /refresh endpoint.
/// </summary>
public record IdentityRefreshRequest
{
    public string RefreshToken { get; init; } = string.Empty;
}

/// <summary>
/// Identity register error response (400).
/// </summary>
public record IdentityErrorResponse
{
    public string? Title { get; init; }
    public int Status { get; init; }
    public Dictionary<string, string[]>? Errors { get; init; }
}

// ===== Server-side only =====

/// <summary>
/// Stored in TokenCacheService. Contains both tokens.
/// The refresh token is managed by Identity (no custom DB table).
/// </summary>
public record TokenData
{
    public string AccessToken { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiry { get; init; }
    public DateTime SessionAbsoluteExpiry { get; init; }
    public TimeSpan RenewalBuffer { get; init; }
}

/// <summary>
/// Returned by the BFF /api/bff/token-status endpoint.
/// Used by TokenTest page and SessionWatcher in both render modes.
/// </summary>
public record TokenStatusResponse
{
    public bool HasTokenData { get; init; }
    public DateTime ServerTimeUtc { get; init; }
    public DateTime? AccessTokenExpiry { get; init; }
    public DateTime? SessionAbsoluteExpiry { get; init; }
    public double? SecondsUntilAccessExpiry { get; init; }
    public double? SecondsUntilSessionExpiry { get; init; }
    public double? RenewalBufferSeconds { get; init; }
    public bool IsAccessTokenExpired { get; init; }
    public bool IsInRenewalWindow { get; init; }
    public bool IsSessionExpired { get; init; }
}