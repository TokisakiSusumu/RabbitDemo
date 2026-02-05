namespace WebApi.Configuration;

public class JwtSettings
{
    public string Secret { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpirationMinutes { get; set; } = 15;  // Short-lived access token
    public int RefreshTokenExpirationDays { get; set; } = 7;  // Long-lived refresh token
}