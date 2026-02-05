using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Configuration;
using WebApi.Data;

namespace WebApi.Services;

public interface ITokenService
{
    Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)>
        GenerateTokensAsync(ApplicationUser user);
    Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)?>
        RefreshTokensAsync(string accessToken, string refreshToken);
    Task RevokeRefreshTokenAsync(string userId);
    ClaimsPrincipal? ValidateExpiredToken(string token);
}

public class TokenService : ITokenService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly JwtSettings _jwtSettings;

    public TokenService(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        IOptions<JwtSettings> jwtSettings)
    {
        _userManager = userManager;
        _context = context;
        _jwtSettings = jwtSettings.Value;
    }

    public async Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)>
        GenerateTokensAsync(ApplicationUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);

        // Generate Access Token (short-lived: 15 minutes)
        var accessExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes);
        var accessToken = GenerateAccessToken(user, roles, accessExpiry);

        // Generate Refresh Token (long-lived: 7 days)
        var refreshExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);
        var refreshToken = await GenerateRefreshTokenAsync(user.Id, refreshExpiry);

        return (accessToken, refreshToken, accessExpiry, refreshExpiry);
    }

    public async Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)?>
        RefreshTokensAsync(string accessToken, string refreshToken)
    {
        // 1. Validate the expired access token to get the user
        var principal = ValidateExpiredToken(accessToken);
        if (principal == null)
            return null;

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return null;

        // 2. Find and validate the refresh token
        var storedToken = await _context.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == refreshToken && t.UserId == userId);

        if (storedToken == null || !storedToken.IsActive)
            return null;

        // 3. Rotate the refresh token (revoke old, create new)
        storedToken.IsRevoked = true;
        storedToken.ReplacedByToken = Guid.NewGuid().ToString();

        var user = storedToken.User;
        var roles = await _userManager.GetRolesAsync(user);

        // 4. Generate new tokens
        var newAccessExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes);
        var newAccessToken = GenerateAccessToken(user, roles, newAccessExpiry);

        var newRefreshExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);
        var newRefreshToken = await GenerateRefreshTokenAsync(userId, newRefreshExpiry);

        await _context.SaveChangesAsync();

        return (newAccessToken, newRefreshToken, newAccessExpiry, newRefreshExpiry);
    }

    public async Task RevokeRefreshTokenAsync(string userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
        }

        await _context.SaveChangesAsync();
    }

    public ClaimsPrincipal? ValidateExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
            ValidateLifetime = false  // Important: Don't validate lifetime for refresh
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return principal;
        }
        catch
        {
            return null;
        }
    }

    private string GenerateAccessToken(ApplicationUser user, IList<string> roles, DateTime expiry)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email!),
            new(ClaimTypes.Name, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: expiry,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<string> GenerateRefreshTokenAsync(string userId, DateTime expiry)
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        var token = Convert.ToBase64String(randomBytes);

        var refreshToken = new RefreshToken
        {
            Token = token,
            UserId = userId,
            ExpiresAt = expiry,
            CreatedAt = DateTime.UtcNow
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        return token;
    }
}