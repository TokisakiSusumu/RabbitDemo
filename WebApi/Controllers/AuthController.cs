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
        Console.WriteLine($">>> [WEBAPI] Register: Attempting to register {request.Email}");

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            Console.WriteLine($">>> [WEBAPI] Register: Email already exists");
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
            Console.WriteLine($">>> [WEBAPI] Register: Failed - {string.Join(", ", result.Errors.Select(e => e.Description))}");
            return BadRequest(new AuthResponse
            {
                Success = false,
                Errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        await _userManager.AddToRoleAsync(user, "User");
        Console.WriteLine($">>> [WEBAPI] Register: Success for {request.Email}");

        return Ok(new AuthResponse
        {
            Success = true,
            Email = user.Email
        });
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        Console.WriteLine($">>> [WEBAPI] Login: Attempting login for {request.Email}");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            Console.WriteLine($">>> [WEBAPI] Login: User not found");
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Errors = ["Invalid credentials"]
            });
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

        if (!result.Succeeded)
        {
            Console.WriteLine($">>> [WEBAPI] Login: Invalid password");
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Errors = ["Invalid credentials"]
            });
        }

        // Generate both access token and refresh token
        var (accessToken, refreshToken, accessExpiry, refreshExpiry) =
            await _tokenService.GenerateTokensAsync(user);

        var roles = await _userManager.GetRolesAsync(user);

        Console.WriteLine($">>> [WEBAPI] Login: Success - AccessToken expires {accessExpiry}, RefreshToken expires {refreshExpiry}");

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
        Console.WriteLine($">>> [WEBAPI] RefreshToken: Attempting to refresh tokens");

        var result = await _tokenService.RefreshTokensAsync(request.Token, request.RefreshToken);

        if (result == null)
        {
            Console.WriteLine($">>> [WEBAPI] RefreshToken: Invalid or expired tokens");
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

        Console.WriteLine($">>> [WEBAPI] RefreshToken: Success - New tokens generated");

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
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            Console.WriteLine($">>> [WEBAPI] Logout: Revoking all refresh tokens for user {userId}");
            await _tokenService.RevokeRefreshTokenAsync(userId);
        }

        return Ok(new { message = "Logged out successfully" });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserInfo>> GetCurrentUser()
    {
        Console.WriteLine($">>> [WEBAPI] GetCurrentUser: Fetching user info");

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId!);

        if (user == null)
        {
            Console.WriteLine($">>> [WEBAPI] GetCurrentUser: User not found");
            return NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);

        Console.WriteLine($">>> [WEBAPI] GetCurrentUser: Found {user.Email} with roles: {string.Join(", ", roles)}");

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
        Console.WriteLine($">>> [WEBAPI] AssignRole: Assigning {request.Role} to {request.Email}");

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