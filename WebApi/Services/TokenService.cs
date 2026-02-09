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

        Console.WriteLine($">>> [WEBAPI] TokenService: Initialized with ExpirationMinutes={_jwtSettings.ExpirationMinutes}, RefreshDays={_jwtSettings.RefreshTokenExpirationDays}");
    }

    public async Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)>
        GenerateTokensAsync(ApplicationUser user)
    {
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: START for user {user.Email}");
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");

        var roles = await _userManager.GetRolesAsync(user);
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: User roles = [{string.Join(", ", roles)}]");

        // Generate Access Token (short-lived)
        var accessExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes);
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: AccessToken will expire at {accessExpiry:yyyy-MM-dd HH:mm:ss} UTC ({_jwtSettings.ExpirationMinutes} min from now)");

        var accessToken = GenerateAccessToken(user, roles, accessExpiry);
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: AccessToken generated (length={accessToken.Length})");

        // Generate Refresh Token (long-lived)
        var refreshExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: RefreshToken will expire at {refreshExpiry:yyyy-MM-dd HH:mm:ss} UTC ({_jwtSettings.RefreshTokenExpirationDays} days from now)");

        var refreshToken = await GenerateRefreshTokenAsync(user.Id, refreshExpiry);
        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: RefreshToken generated and saved to DB");

        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateTokensAsync: END - Tokens created successfully");

        return (accessToken, refreshToken, accessExpiry, refreshExpiry);
    }

    public async Task<(string AccessToken, string RefreshToken, DateTime AccessExpiry, DateTime RefreshExpiry)?>
        RefreshTokensAsync(string accessToken, string refreshToken)
    {
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: START");
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: AccessToken length = {accessToken?.Length ?? 0}");
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: RefreshToken length = {refreshToken?.Length ?? 0}");

        // 1. Validate the expired access token to get the user
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Step 1 - Validating expired access token...");
        var principal = ValidateExpiredToken(accessToken);
        if (principal == null)
        {
            Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: FAILED - Could not validate expired token");
            return null;
        }

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var userEmail = principal.FindFirstValue(ClaimTypes.Email);
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Token belongs to userId={userId}, email={userEmail}");

        if (string.IsNullOrEmpty(userId))
        {
            Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: FAILED - No user ID in token");
            return null;
        }

        // 2. Find and validate the refresh token
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Step 2 - Looking up RefreshToken in database...");
        var storedToken = await _context.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == refreshToken && t.UserId == userId);

        if (storedToken == null)
        {
            Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: FAILED - RefreshToken not found in DB or doesn't match user");
            return null;
        }

        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Found RefreshToken in DB:");
        Console.WriteLine($">>>   - Token ID: {storedToken.Id}");
        Console.WriteLine($">>>   - Created: {storedToken.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - Expires: {storedToken.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - IsRevoked: {storedToken.IsRevoked}");
        Console.WriteLine($">>>   - IsExpired: {storedToken.IsExpired}");
        Console.WriteLine($">>>   - IsActive: {storedToken.IsActive}");

        if (!storedToken.IsActive)
        {
            Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: FAILED - RefreshToken is not active (revoked or expired)");
            return null;
        }

        // 3. Rotate the refresh token (revoke old, create new)
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Step 3 - Rotating tokens (revoking old, creating new)...");
        storedToken.IsRevoked = true;
        storedToken.ReplacedByToken = Guid.NewGuid().ToString();
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Old RefreshToken marked as revoked");

        var user = storedToken.User;
        var roles = await _userManager.GetRolesAsync(user);
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: User roles = [{string.Join(", ", roles)}]");

        // 4. Generate new tokens
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Step 4 - Generating new tokens...");
        var newAccessExpiry = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes);
        var newAccessToken = GenerateAccessToken(user, roles, newAccessExpiry);
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: New AccessToken expires at {newAccessExpiry:yyyy-MM-dd HH:mm:ss} UTC");

        var newRefreshExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);
        var newRefreshToken = await GenerateRefreshTokenAsync(userId, newRefreshExpiry);
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: New RefreshToken expires at {newRefreshExpiry:yyyy-MM-dd HH:mm:ss} UTC");

        await _context.SaveChangesAsync();
        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: Database changes saved");

        Console.WriteLine($">>> [WEBAPI] TokenService.RefreshTokensAsync: END - SUCCESS - New tokens generated");
        return (newAccessToken, newRefreshToken, newAccessExpiry, newRefreshExpiry);
    }

    public async Task RevokeRefreshTokenAsync(string userId)
    {
        Console.WriteLine($">>> [WEBAPI] TokenService.RevokeRefreshTokenAsync: Revoking all tokens for userId={userId}");

        var tokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        Console.WriteLine($">>> [WEBAPI] TokenService.RevokeRefreshTokenAsync: Found {tokens.Count} active tokens to revoke");

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            Console.WriteLine($">>> [WEBAPI] TokenService.RevokeRefreshTokenAsync: Revoked token ID={token.Id}");
        }

        await _context.SaveChangesAsync();
        Console.WriteLine($">>> [WEBAPI] TokenService.RevokeRefreshTokenAsync: All tokens revoked and saved");
    }

    public ClaimsPrincipal? ValidateExpiredToken(string token)
    {
        Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: Validating token (ignoring expiration)...");

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
                Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: FAILED - Invalid token algorithm");
                return null;
            }

            Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: SUCCESS - Token is valid (signature OK)");
            Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: Token was issued at {jwtToken.IssuedAt:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: Token expired at {jwtToken.ValidTo:yyyy-MM-dd HH:mm:ss} UTC");

            return principal;
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> [WEBAPI] TokenService.ValidateExpiredToken: EXCEPTION - {ex.Message}");
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

        Console.WriteLine($">>> [WEBAPI] TokenService.GenerateRefreshTokenAsync: Created new RefreshToken with ID={refreshToken.Id}");

        return token;
    }
}