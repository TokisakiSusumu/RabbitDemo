using Shared.Auth;

namespace BlazorApp1.Client.Services;

/// <summary>
/// Interface for making authenticated API calls.
/// 
/// Server implementation: Uses AuthService with JWT directly.
/// WASM implementation: Calls BFF proxy endpoints on Blazor Server (cookie auth).
/// </summary>
public interface IApiClient
{
    Task<UserInfo?> GetMyInfoAsync();
}
