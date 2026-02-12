using Shared.Auth;
using System.Net.Http.Json;

namespace BlazorApp1.Client.Services;

public class WasmApiClient : IApiClient
{
    private readonly HttpClient _httpClient;

    public WasmApiClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<UserInfo?> GetMyInfoAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/bff/me");
            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<UserInfo>();
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WASM] GetMyInfoAsync: {ex.Message}");
            return null;
        }
    }

    public async Task<TokenStatusResponse?> GetTokenStatusAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/bff/token-status");
            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<TokenStatusResponse>();
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WASM] GetTokenStatusAsync: {ex.Message}");
            return null;
        }
    }
}