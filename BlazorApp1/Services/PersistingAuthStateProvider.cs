using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Web;
using Shared.Auth;
using System.Diagnostics;
using System.Security.Claims;

namespace BlazorApp1.Services;

/// <summary>
/// Server-side AuthenticationStateProvider that:
/// 1. Reads auth state from HTTP context (cookie)
/// 2. Persists auth state to WASM via PersistentComponentState
/// 
/// This allows InteractiveAuto pages to have auth in both modes.
/// </summary>
public class PersistingAuthStateProvider : ServerAuthenticationStateProvider, IDisposable
{
    private readonly PersistentComponentState _state;
    private readonly PersistingComponentStateSubscription _subscription;
    private Task<AuthenticationState>? _authStateTask;

    public PersistingAuthStateProvider(PersistentComponentState state)
    {
        Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: Constructor called");
        _state = state;
        
        AuthenticationStateChanged += OnAuthenticationStateChanged;
        _subscription = state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
    }

    private void OnAuthenticationStateChanged(Task<AuthenticationState> task)
    {
        Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: AuthenticationStateChanged event fired");
        _authStateTask = task;
    }

    private async Task OnPersistingAsync()
    {
        Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: OnPersistingAsync - Persisting auth state to WASM");
        
        if (_authStateTask is null)
        {
            Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: No auth state task, getting current state");
            _authStateTask = GetAuthenticationStateAsync();
        }

        var authState = await _authStateTask;
        var principal = authState.User;

        Console.WriteLine($">>> [SERVER] PersistingAuthStateProvider: IsAuthenticated={principal.Identity?.IsAuthenticated}, Name={principal.Identity?.Name}");

        if (principal.Identity?.IsAuthenticated == true)
        {
            var claims = principal.Claims
                .Select(c => new ClaimData { Type = c.Type, Value = c.Value })
                .ToList();

            Console.WriteLine($">>> [SERVER] PersistingAuthStateProvider: Persisting {claims.Count} claims");
            
            _state.PersistAsJson(nameof(UserAuthData), new UserAuthData
            {
                IsAuthenticated = true,
                Claims = claims
            });
        }
        else
        {
            Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: User not authenticated, persisting empty state");
            _state.PersistAsJson(nameof(UserAuthData), new UserAuthData
            {
                IsAuthenticated = false,
                Claims = []
            });
        }
    }

    public void Dispose()
    {
        Console.WriteLine(">>> [SERVER] PersistingAuthStateProvider: Disposing");
        _subscription.Dispose();
        AuthenticationStateChanged -= OnAuthenticationStateChanged;
    }
}