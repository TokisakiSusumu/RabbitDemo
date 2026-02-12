using BlazorApp1.Client.Services;
using Shared.Auth;

namespace BlazorApp1.Services;

/// <summary>
/// Server implementation - calls WebApi directly using JWT from TokenCacheService.
/// Used when components render in Server mode.
/// </summary>
public class ServerApiClient : IApiClient
{
    private readonly IAuthService _authService;

    public ServerApiClient(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<UserInfo?> GetMyInfoAsync()
    {
        Console.WriteLine("[SERVER] ServerApiClient → GetMyInfoAsync");
        return await _authService.GetAsync<UserInfo>("api/auth/me");
    }
}
