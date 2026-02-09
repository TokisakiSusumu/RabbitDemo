using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.Auth;
using System.Security.Claims;
using WebApi.Data;
using WebApi.Services;

namespace WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        Console.WriteLine($"");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($">>> [WEBAPI] AuthController.Register: START");
        Console.WriteLine($">>> [WEBAPI] AuthController.Register: Email={request.Email}");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.Register: FAILED - Email already exists");
            return BadRequest(new AuthResponse
            {
                Success = false,
                Errors = ["Email already registered"]
            });
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.Register: FAILED - {string.Join(", ", result.Errors.Select(e => e.Description))}");
            return BadRequest(new AuthResponse
            {
                Success = false,
                Errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        await _userManager.AddToRoleAsync(user, "User");
        Console.WriteLine($">>> [WEBAPI] AuthController.Register: SUCCESS - User created with 'User' role");

        return Ok(new AuthResponse
        {
            Success = true,
            Email = user.Email
        });
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        Console.WriteLine($"");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($">>> [WEBAPI] AuthController.Login: START");
        Console.WriteLine($">>> [WEBAPI] AuthController.Login: Email={request.Email}");
        Console.WriteLine($">>> [WEBAPI] AuthController.Login: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.Login: FAILED - User not found");
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Errors = ["Invalid credentials"]
            });
        }

        Console.WriteLine($">>> [WEBAPI] AuthController.Login: User found, checking password...");
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

        if (!result.Succeeded)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.Login: FAILED - Invalid password");
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Errors = ["Invalid credentials"]
            });
        }

        Console.WriteLine($">>> [WEBAPI] AuthController.Login: Password valid, generating tokens...");

        // Generate both access token and refresh token
        var (accessToken, refreshToken, accessExpiry, refreshExpiry) =
            await _tokenService.GenerateTokensAsync(user);

        var roles = await _userManager.GetRolesAsync(user);

        Console.WriteLine($"");
        Console.WriteLine($">>> [WEBAPI] AuthController.Login: SUCCESS");
        Console.WriteLine($">>>   - AccessToken expires: {accessExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - RefreshToken expires: {refreshExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - Roles: [{string.Join(", ", roles)}]");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($"");

        return Ok(new AuthResponse
        {
            Success = true,
            Token = accessToken,
            RefreshToken = refreshToken,
            Expiration = accessExpiry,
            Email = user.Email,
            Roles = roles.ToList()
        });
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        Console.WriteLine($"");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($">>> [WEBAPI] AuthController.RefreshToken: START");
        Console.WriteLine($">>> [WEBAPI] AuthController.RefreshToken: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        var result = await _tokenService.RefreshTokensAsync(request.Token, request.RefreshToken);

        if (result == null)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.RefreshToken: FAILED - Token refresh failed");
            Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Errors = ["Invalid or expired refresh token"]
            });
        }

        var (accessToken, refreshToken, accessExpiry, refreshExpiry) = result.Value;

        // Get user info from the new token
        var principal = _tokenService.ValidateExpiredToken(accessToken);
        var email = principal?.FindFirstValue(ClaimTypes.Email);
        var roles = principal?.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList() ?? [];

        Console.WriteLine($"");
        Console.WriteLine($">>> [WEBAPI] AuthController.RefreshToken: SUCCESS");
        Console.WriteLine($">>>   - New AccessToken expires: {accessExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - New RefreshToken expires: {refreshExpiry:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($">>>   - User: {email}");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($"");

        return Ok(new AuthResponse
        {
            Success = true,
            Token = accessToken,
            RefreshToken = refreshToken,
            Expiration = accessExpiry,
            Email = email,
            Roles = roles
        });
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        Console.WriteLine($"");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($">>> [WEBAPI] AuthController.Logout: START");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.Logout: Revoking tokens for userId={userId}");
            await _tokenService.RevokeRefreshTokenAsync(userId);
        }

        Console.WriteLine($">>> [WEBAPI] AuthController.Logout: SUCCESS");
        return Ok(new { message = "Logged out successfully" });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserInfo>> GetCurrentUser()
    {
        Console.WriteLine($"");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");
        Console.WriteLine($">>> [WEBAPI] AuthController.GetCurrentUser: START");
        Console.WriteLine($">>> [WEBAPI] AuthController.GetCurrentUser: Current UTC time = {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        Console.WriteLine($">>> [WEBAPI] AuthController.GetCurrentUser: UserId from token = {userId}");

        var user = await _userManager.FindByIdAsync(userId!);

        if (user == null)
        {
            Console.WriteLine($">>> [WEBAPI] AuthController.GetCurrentUser: FAILED - User not found");
            return NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);

        Console.WriteLine($">>> [WEBAPI] AuthController.GetCurrentUser: SUCCESS");
        Console.WriteLine($">>>   - Email: {user.Email}");
        Console.WriteLine($">>>   - Roles: [{string.Join(", ", roles)}]");
        Console.WriteLine($"¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T");

        return Ok(new UserInfo
        {
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roles.ToList()
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
    {
        Console.WriteLine($">>> [WEBAPI] AuthController.AssignRole: Assigning {request.Role} to {request.Email}");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
            return NotFound("User not found");

        var result = await _userManager.AddToRoleAsync(user, request.Role);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok($"Role '{request.Role}' assigned to {request.Email}");
    }
}

public record AssignRoleRequest
{
    public string Email { get; init; } = string.Empty;
    public string Role { get; init; } = string.Empty;
}