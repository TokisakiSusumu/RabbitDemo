using BlazorApp1.Client.Services;
using Shared.Auth;

namespace BlazorApp1.Services;

public class ServerApiClient : IApiClient
{
    private readonly IAuthService _authService;

    public ServerApiClient(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<UserInfo?> GetMyInfoAsync()
    {
        Console.WriteLine("[SERVER] ServerApiClient.GetMyInfoAsync");
        return await _authService.GetAsync<UserInfo>("api/auth/me");
    }

    public Task<TokenStatusResponse?> GetTokenStatusAsync()
    {
        var status = _authService.GetTokenStatus();
        return Task.FromResult<TokenStatusResponse?>(status);
    }
}