using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Routing;
using Shared.Auth;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;

namespace BlazorApp1.Client.Services;

/// <summary>
/// WASM-side AuthenticationStateProvider that:
/// 1. Reads initial auth state from server via PersistentComponentState (on page load)
/// 2. Revalidates session on every navigation via BFF call
/// 3. Calls NotifyAuthenticationStateChanged when session expires
///    ¡ú NavMenu updates instantly, AuthorizeRouteView renders NotAuthorized ¡ú RedirectToLogin
///
/// WHY THIS WORKS:
/// - AuthorizeView (NavMenu) and AuthorizeRouteView both subscribe to AuthenticationStateChanged
/// - When we fire NotifyAuthenticationStateChanged, ALL auth-aware components re-render
/// - No timers, no polling ¡ª triggered by user navigation only (like a normal web app)
/// </summary>
public class PersistentAuthStateProvider : AuthenticationStateProvider, IDisposable
{
    private static readonly Task<AuthenticationState> _unauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly HttpClient _httpClient;
    private readonly NavigationManager _nav;

    private Task<AuthenticationState> _authStateTask = _unauthenticatedTask;
    private bool _isAuthenticated;

    public PersistentAuthStateProvider(
        PersistentComponentState state,
        HttpClient httpClient,
        NavigationManager nav)
    {
        _httpClient = httpClient;
        _nav = nav;

        Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: Constructor called");

        // ©¤©¤ Step 1: Read initial state persisted from server prerender ©¤©¤
        if (!state.TryTakeFromJson<UserAuthData>(nameof(UserAuthData), out var authData) || authData is null)
        {
            Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: No persisted auth data found");
            return;
        }

        if (!authData.IsAuthenticated)
        {
            Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: User not authenticated");
            return;
        }

        Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Restoring {authData.Claims.Count} claims");

        var claims = authData.Claims.Select(c => new Claim(c.Type, c.Value)).ToList();
        _authStateTask = Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, "Persisted"))));
        _isAuthenticated = true;

        // ©¤©¤ Step 2: Listen for navigations to revalidate ©¤©¤
        _nav.LocationChanged += OnLocationChanged;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return _authStateTask;
    }

    /// <summary>
    /// Fires on every Blazor navigation (user clicks a link, NavLink, etc.)
    /// Calls the BFF to check if the session is still alive.
    /// If dead ¡ú marks as unauthenticated ¡ú NotifyAuthenticationStateChanged
    /// ¡ú NavMenu updates + AuthorizeRouteView renders NotAuthorized ¡ú RedirectToLogin
    /// </summary>
    private async void OnLocationChanged(object? sender, LocationChangedEventArgs e)
    {
        // Only check if we were authenticated
        if (!_isAuthenticated) return;

        Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Navigation detected, verifying session...");

        try
        {
            var response = await _httpClient.GetAsync("/api/bff/token-status");

            // 401 = cookie rejected by server = session dead
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: 401 ¡ª session dead, marking unauthenticated");
                MarkAsUnauthenticated();
                return;
            }

            if (response.IsSuccessStatusCode)
            {
                var status = await response.Content.ReadFromJsonAsync<TokenStatusResponse>();

                if (status == null || !status.HasTokenData || status.IsAccessTokenExpired || status.IsSessionExpired)
                {
                    Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Session expired (HasData={status?.HasTokenData}, TokenExpired={status?.IsAccessTokenExpired}, SessionExpired={status?.IsSessionExpired})");
                    MarkAsUnauthenticated();
                }
            }
        }
        catch (Exception ex)
        {
            // Network error (e.g. server down) ¡ª don't log out, just skip
            Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Check failed: {ex.Message}");
        }
    }

    private void MarkAsUnauthenticated()
    {
        _isAuthenticated = false;
        _authStateTask = _unauthenticatedTask;

        // This is the KEY call:
        // - AuthorizeView (NavMenu) subscribes ¡ú re-renders ¡ú shows Login/Register
        // - AuthorizeRouteView subscribes ¡ú re-renders ¡ú NotAuthorized ¡ú RedirectToLogin
        NotifyAuthenticationStateChanged(_authStateTask);

        // Unsubscribe ¡ª no more checks needed
        _nav.LocationChanged -= OnLocationChanged;
    }

    public void Dispose()
    {
        _nav.LocationChanged -= OnLocationChanged;
    }
}

/// <summary>
/// Data structure for persisting auth state ¡ª must match server-side definition
/// </summary>
public class UserAuthData
{
    public bool IsAuthenticated { get; set; }
    public List<ClaimData> Claims { get; set; } = [];
}

public class ClaimData
{
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}