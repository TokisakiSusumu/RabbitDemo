using Shared.Auth;
using System.Net.Http.Json;

namespace BlazorApp1.Client.Services;

/// <summary>
/// WASM implementation - calls BFF endpoints on Blazor Server.
/// 
/// Flow: WASM HttpClient → /api/bff/me (cookie auth) → Blazor Server → WebApi (JWT auth)
/// Cookies are sent automatically for same-origin requests.
/// </summary>
public class WasmApiClient : IApiClient
{
    private readonly HttpClient _httpClient;

    public WasmApiClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
        Console.WriteLine("[WASM] WasmApiClient created");
    }

    public async Task<UserInfo?> GetMyInfoAsync()
    {
        try
        {
            Console.WriteLine("[WASM] Calling /api/bff/me...");
            var response = await _httpClient.GetAsync("/api/bff/me");
            Console.WriteLine($"[WASM] /api/bff/me → {(int)response.StatusCode}");

            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<UserInfo>();

            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WASM] API call failed: {ex.Message}");
            return null;
        }
    }
}
