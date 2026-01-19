using Shared.Auth;

namespace BlazorApp1.Services;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<UserInfo?> GetCurrentUserAsync();
    Task LogoutAsync();
    Task<string?> GetTokenAsync();
}