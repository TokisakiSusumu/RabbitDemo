using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace BlazorApp1.Client.Services;

/// <summary>
/// WASM-side AuthenticationStateProvider that:
/// 1. Reads auth state persisted from server via PersistentComponentState
/// 2. Provides auth state to all WASM components
/// 
/// This enables InteractiveAuto pages to have auth in WASM mode.
/// </summary>
public class PersistentAuthStateProvider : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> _defaultUnauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly Task<AuthenticationState> _authStateTask = _defaultUnauthenticatedTask;

    public PersistentAuthStateProvider(PersistentComponentState state)
    {
        Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: Constructor called");
        
        if (!state.TryTakeFromJson<UserAuthData>(nameof(UserAuthData), out var authData) || authData is null)
        {
            Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: No persisted auth data found");
            return;
        }

        Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Found persisted data, IsAuthenticated={authData.IsAuthenticated}");

        if (!authData.IsAuthenticated)
        {
            Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: User not authenticated");
            return;
        }

        Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Restoring {authData.Claims.Count} claims");

        var claims = authData.Claims.Select(c => new Claim(c.Type, c.Value)).ToList();
        
        foreach (var claim in claims)
        {
            Console.WriteLine($">>> [WASM] PersistentAuthStateProvider: Claim {claim.Type}={claim.Value}");
        }

        _authStateTask = Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, "Persisted"))));
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        Console.WriteLine(">>> [WASM] PersistentAuthStateProvider: GetAuthenticationStateAsync called");
        return _authStateTask;
    }
}

/// <summary>
/// Data structure for persisting auth state - must match server-side definition
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
