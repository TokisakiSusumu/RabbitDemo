using System.Net.Http.Headers;
using System.Net.Http.Json;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Shared.Auth;

namespace BlazorApp1.Services;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly ProtectedLocalStorage _localStorage;
    private const string TokenKey = "authToken";

    public AuthService(HttpClient httpClient, ProtectedLocalStorage localStorage)
    {
        _httpClient = httpClient;
        _localStorage = localStorage;
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/login", request);
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();

        if (result?.Success == true && !string.IsNullOrEmpty(result.Token))
        {
            await _localStorage.SetAsync(TokenKey, result.Token);
        }

        return result ?? new AuthResponse { Success = false, Errors = ["Unknown error"] };
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/register", request);
        var result = await response.Content.ReadFromJsonAsync<AuthResponse>();
        return result ?? new AuthResponse { Success = false, Errors = ["Unknown error"] };
    }

    public async Task<UserInfo?> GetCurrentUserAsync()
    {
        var token = await GetTokenAsync();
        if (string.IsNullOrEmpty(token))
            return null;

        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _httpClient.GetAsync("api/auth/me");
        if (response.IsSuccessStatusCode)
        {
            return await response.Content.ReadFromJsonAsync<UserInfo>();
        }

        return null;
    }

    public async Task LogoutAsync()
    {
        await _localStorage.DeleteAsync(TokenKey);
        _httpClient.DefaultRequestHeaders.Authorization = null;
    }

    public async Task<string?> GetTokenAsync()
    {
        var result = await _localStorage.GetAsync<string>(TokenKey);
        return result.Success ? result.Value : null;
    }
}