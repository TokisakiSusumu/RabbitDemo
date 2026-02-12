using Shared.Auth;

namespace BlazorApp1.Client.Services;

public interface IApiClient
{
    Task<UserInfo?> GetMyInfoAsync();
    Task<TokenStatusResponse?> GetTokenStatusAsync();
}