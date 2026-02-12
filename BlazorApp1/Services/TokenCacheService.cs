using Shared.Auth;
using System.Collections.Concurrent;

namespace BlazorApp1.Services;

/// <summary>
/// Stores JWT tokens server-side in memory, keyed by user email.
/// 
/// WHY: Cookies can't be updated during SignalR connections (InteractiveServer).
/// Storing tokens here means refresh can happen in ANY context.
/// 
/// NOTE: Tokens are lost on server restart → users must re-login. 
/// For production with multiple servers, use IDistributedCache (Redis).
/// </summary>
public class TokenCacheService
{
    private readonly ConcurrentDictionary<string, TokenData> _tokens = new();

    public void Store(string userEmail, TokenData tokenData)
    {
        _tokens[userEmail.ToLowerInvariant()] = tokenData;
        Console.WriteLine($"[AUTH-CACHE] Stored tokens for {userEmail}, access expires {tokenData.AccessTokenExpiry:HH:mm:ss} UTC");
    }

    public TokenData? Get(string userEmail)
    {
        _tokens.TryGetValue(userEmail.ToLowerInvariant(), out var data);
        return data;
    }

    public bool HasTokens(string userEmail)
    {
        return _tokens.ContainsKey(userEmail.ToLowerInvariant());
    }

    public void Remove(string userEmail)
    {
        _tokens.TryRemove(userEmail.ToLowerInvariant(), out _);
        Console.WriteLine($"[AUTH-CACHE] Removed tokens for {userEmail}");
    }
}
