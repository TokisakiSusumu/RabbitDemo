namespace Shared.Auth;

// ===== Custom DTOs =====

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

/// <summary>
/// Sent by BlazorApp1 to WebApi after external OAuth completes.
/// WebApi creates/links the user and returns bearer tokens.
/// </summary>
public record ExternalLoginRequest
{
    public string Provider { get; init; } = string.Empty;
    public string ProviderUserId { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
}

// ===== Identity API response DTOs =====

public record IdentityTokenResponse
{
    public string TokenType { get; init; } = string.Empty;
    public string AccessToken { get; init; } = string.Empty;
    public long ExpiresIn { get; init; }
    public string RefreshToken { get; init; } = string.Empty;
}

public record IdentityRefreshRequest
{
    public string RefreshToken { get; init; } = string.Empty;
}

// ===== Server-side only =====

public record TokenData
{
    public string AccessToken { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiry { get; init; }
    public DateTime SessionAbsoluteExpiry { get; init; }
    public TimeSpan RenewalBuffer { get; init; }
}

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