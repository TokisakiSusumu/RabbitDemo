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

    // Adding a new method? Just copy this pattern:
    //   public Task<List<OrderDto>?> GetOrdersAsync()
    //       => GetAsync<List<OrderDto>>("/api/bff/orders");

    public Task<UserInfo?> GetMyInfoAsync()
        => GetAsync<UserInfo>("/api/bff/me");

    public Task<TokenStatusResponse?> GetTokenStatusAsync()
        => GetAsync<TokenStatusResponse>("/api/bff/token-status");

    private async Task<T?> GetAsync<T>(string path)
    {
        try
        {
            var response = await _httpClient.GetAsync(path);
            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<T>()
                : default;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WASM] GET {path}: {ex.Message}");
            return default;
        }
    }
}