namespace Shared.Auth;

public record RegisterRequest
{
    public string Email { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
}

public record LoginRequest
{
    public string Email { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
}

public record AuthResponse
{
    public bool Success { get; init; }
    public string? Token { get; init; }
    public string? RefreshToken { get; init; }  // NEW: For token refresh
    public DateTime? Expiration { get; init; }
    public string? Email { get; init; }
    public List<string> Roles { get; init; } = [];
    public List<string> Errors { get; init; } = [];
}

public record UserInfo
{
    public string Email { get; init; } = string.Empty;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public List<string> Roles { get; init; } = [];
}

// NEW: For refresh token requests
public record RefreshTokenRequest
{
    public string Token { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
}

// NEW: For storing tokens in cookie
public record TokenData
{
    public string AccessToken { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiry { get; init; }
    public DateTime RefreshTokenExpiry { get; init; }
}