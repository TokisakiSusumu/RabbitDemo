using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Shared.Auth;
using System.Net.Http.Json;
using System.Security.Claims;

namespace BlazorApp1.Client.Services;

public class PersistentAuthStateProvider : AuthenticationStateProvider, IDisposable
{
    private readonly NavigationManager _navigation;
    private readonly HttpClient _httpClient;
    private AuthenticationState _currentState;

    public PersistentAuthStateProvider(
        PersistentComponentState persistentState,
        NavigationManager navigation,
        HttpClient httpClient)
    {
        _navigation = navigation;
        _httpClient = httpClient;

        // Read initial state from server prerender (one-shot)
        if (persistentState.TryTakeFromJson<UserAuthData>(nameof(UserAuthData), out var authData)
            && authData?.IsAuthenticated == true)
        {
            Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Got {authData.Claims.Count} claims from server");
            _currentState = new AuthenticationState(CreatePrincipal(authData.Claims));
        }
        else
        {
            Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: No persisted auth (anonymous)");
            _currentState = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        _navigation.LocationChanged += OnLocationChanged;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => Task.FromResult(_currentState);

    private async void OnLocationChanged(object? sender, Microsoft.AspNetCore.Components.Routing.LocationChangedEventArgs e)
    {
        Console.WriteLine($">>> [WASM] LocationChanged ¡ú revalidating auth...");
        try
        {
            var response = await _httpClient.GetAsync("/api/bff/token-status");

            if (!response.IsSuccessStatusCode)
            {
                SetAnonymous($"BFF returned {(int)response.StatusCode}");
                return;
            }

            // Safety: if we got HTML back (redirect was followed), this will fail gracefully
            TokenStatusResponse? status;
            try
            {
                status = await response.Content.ReadFromJsonAsync<TokenStatusResponse>();
            }
            catch
            {
                Console.WriteLine(">>> [WASM] Failed to parse token-status (likely got HTML redirect)");
                SetAnonymous("Unparseable response");
                return;
            }

            if (status == null || !status.HasTokenData || status.IsAccessTokenExpired || status.IsSessionExpired)
            {
                SetAnonymous("Token/session expired");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> [WASM] Auth revalidation error: {ex.Message}");
        }
    }

    private void SetAnonymous(string reason)
    {
        if (_currentState.User.Identity?.IsAuthenticated != true)
            return;

        Console.WriteLine($">>> [WASM] Auth state ¡ú ANONYMOUS ({reason})");
        _currentState = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        NotifyAuthenticationStateChanged(Task.FromResult(_currentState));
    }

    private static ClaimsPrincipal CreatePrincipal(List<ClaimData> claims)
    {
        var claimsList = claims.Select(c => new Claim(c.Type, c.Value)).ToList();
        return new ClaimsPrincipal(new ClaimsIdentity(claimsList, "ServerPersisted"));
    }

    public void Dispose()
    {
        _navigation.LocationChanged -= OnLocationChanged;
    }
}