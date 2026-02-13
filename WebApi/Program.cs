using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Shared.Auth;
using System.Security.Claims;
using WebApi.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

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

var tokenLifetimeSeconds = builder.Configuration.GetValue("AuthSettings:TokenLifetimeSeconds", 3600);
var maxSessionHours = builder.Configuration.GetValue("AuthSettings:MaxSessionHours", 24);

Console.WriteLine($">>> [WEBAPI] Token lifetime: {tokenLifetimeSeconds}s, Max session: {maxSessionHours}h");

builder.Services.Configure<BearerTokenOptions>(IdentityConstants.BearerScheme, options =>
{
    options.BearerTokenExpiration = TimeSpan.FromSeconds(tokenLifetimeSeconds);
    options.RefreshTokenExpiration = TimeSpan.FromHours(maxSessionHours);
});

builder.Services.AddAuthorization();

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
//  Identity API endpoints (login, refresh, etc.)
// =====================================================================
app.MapGroup("/api/identity").MapIdentityApi<ApplicationUser>();

// =====================================================================
//  Custom endpoints
// =====================================================================

// Register with role assignment
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
    Console.WriteLine($">>> [WEBAPI] Register SUCCESS: {request.Email}");
    return Results.Ok(new { success = true, email = user.Email });
});

// External login: creates/links user from external provider, returns bearer tokens
// Called by BlazorApp1 BFF after Microsoft OAuth callback
app.MapPost("/api/auth/external-login", async (
    ExternalLoginRequest request,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) =>
{
    Console.WriteLine($">>> [WEBAPI] ExternalLogin: {request.Provider} / {request.Email}");

    // Step 1: Find user by external login
    var user = await userManager.FindByLoginAsync(request.Provider, request.ProviderUserId);

    if (user == null)
    {
        // Step 2: Try find by email (user may have registered with password first)
        user = await userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            // Step 3: Create new user
            user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = true, // Microsoft already verified the email
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            var createResult = await userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                var errors = createResult.Errors.Select(e => e.Description).ToList();
                Console.WriteLine($">>> [WEBAPI] ExternalLogin CREATE FAILED: {string.Join(", ", errors)}");
                return Results.BadRequest(new { errors });
            }

            await userManager.AddToRoleAsync(user, "User");
            Console.WriteLine($">>> [WEBAPI] ExternalLogin: Created user {request.Email}");
        }

        // Link external login to user
        var loginInfo = new UserLoginInfo(request.Provider, request.ProviderUserId, request.Provider);
        var linkResult = await userManager.AddLoginAsync(user, loginInfo);
        if (!linkResult.Succeeded)
        {
            Console.WriteLine($">>> [WEBAPI] ExternalLogin LINK FAILED: {string.Join(", ", linkResult.Errors.Select(e => e.Description))}");
            // Non-fatal: user exists, login linked might already exist
        }
    }

    Console.WriteLine($">>> [WEBAPI] ExternalLogin: Signing in {user.Email}");

    // Step 4: Generate bearer token using Identity's mechanism
    // This returns the same format as /api/identity/login
    var principal = await signInManager.CreateUserPrincipalAsync(user);
    return TypedResults.SignIn(principal, authenticationScheme: IdentityConstants.BearerScheme);
});

// User info with roles
app.MapGet("/api/auth/me", async (
    HttpContext context,
    UserManager<ApplicationUser> userManager) =>
{
    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId))
        return Results.Unauthorized();

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