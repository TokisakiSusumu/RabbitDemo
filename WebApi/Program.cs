using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Shared.Auth;
using System.Security.Claims;
using WebApi.Data;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity with built-in API endpoints (replaces our custom AuthController + TokenService)
// This gives us: /login, /refresh, /register (built-in), /manage/* endpoints
// And sets up bearer token authentication automatically
builder.Services
    .AddIdentityApiEndpoints<ApplicationUser>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength = 6;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// Configure bearer token lifetimes (replaces our custom JwtSettings)
var tokenLifetimeSeconds = builder.Configuration.GetValue("AuthSettings:TokenLifetimeSeconds", 3600);
var maxSessionHours = builder.Configuration.GetValue("AuthSettings:MaxSessionHours", 24);

Console.WriteLine($">>> [WEBAPI] Token lifetime: {tokenLifetimeSeconds}s, Max session: {maxSessionHours}h");

builder.Services.Configure<BearerTokenOptions>(IdentityConstants.BearerScheme, options =>
{
    options.BearerTokenExpiration = TimeSpan.FromSeconds(tokenLifetimeSeconds);
    options.RefreshTokenExpiration = TimeSpan.FromHours(maxSessionHours);
});

builder.Services.AddAuthorization();

// CORS for Blazor app
builder.Services.AddCors(options =>
{
    options.AddPolicy("BlazorApp", policy =>
    {
        policy.WithOrigins("http://localhost:5161", "https://localhost:7157")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Seed roles
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Admin", "User", "Manager" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }
}

app.UseCors("BlazorApp");
app.UseAuthentication();
app.UseAuthorization();

// =====================================================================
//  Identity API endpoints (built-in login, refresh, etc.)
//  Maps: POST /api/identity/login, POST /api/identity/refresh, etc.
// =====================================================================
app.MapGroup("/api/identity").MapIdentityApi<ApplicationUser>();

// =====================================================================
//  Custom endpoints (register with role + user info with roles)
// =====================================================================

// Custom register: creates user AND assigns "User" role
// (MapIdentityApi's built-in /register doesn't assign roles)
app.MapPost("/api/auth/register", async (
    RegisterRequest request,
    UserManager<ApplicationUser> userManager) =>
{
    Console.WriteLine($">>> [WEBAPI] Register: {request.Email}");

    var user = new ApplicationUser
    {
        UserName = request.Email,
        Email = request.Email,
        FirstName = request.FirstName,
        LastName = request.LastName
    };

    var result = await userManager.CreateAsync(user, request.Password);
    if (!result.Succeeded)
    {
        var errors = result.Errors.Select(e => e.Description).ToList();
        Console.WriteLine($">>> [WEBAPI] Register FAILED: {string.Join(", ", errors)}");
        return Results.BadRequest(new { success = false, errors });
    }

    await userManager.AddToRoleAsync(user, "User");
    Console.WriteLine($">>> [WEBAPI] Register SUCCESS: {request.Email} (assigned 'User' role)");

    return Results.Ok(new { success = true, email = user.Email });
});

// User info with roles (MapIdentityApi's /manage/info doesn't include roles conveniently)
app.MapGet("/api/auth/me", async (
    HttpContext context,
    UserManager<ApplicationUser> userManager) =>
{
    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId))
    {
        Console.WriteLine(">>> [WEBAPI] GetMe: no user ID in token");
        return Results.Unauthorized();
    }

    var user = await userManager.FindByIdAsync(userId);
    if (user == null) return Results.NotFound();

    var roles = await userManager.GetRolesAsync(user);
    Console.WriteLine($">>> [WEBAPI] GetMe: {user.Email}, roles=[{string.Join(",", roles)}]");

    return Results.Ok(new UserInfo
    {
        Email = user.Email!,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Roles = roles.ToList()
    });
}).RequireAuthorization();

app.Run();