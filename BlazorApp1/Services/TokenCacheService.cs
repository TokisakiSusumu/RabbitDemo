using Shared.Auth;
using System.Collections.Concurrent;

namespace BlazorApp1.Services;

public class TokenCacheService
{
    private readonly ConcurrentDictionary<string, TokenData> _tokens = new();

    public void Store(string userEmail, TokenData tokenData)
    {
        _tokens[userEmail.ToLowerInvariant()] = tokenData;
        Console.WriteLine($"[TOKEN-CACHE] Stored for {userEmail}: access expires {tokenData.AccessTokenExpiry:HH:mm:ss}, session expires {tokenData.SessionAbsoluteExpiry:HH:mm:ss}, renewBuffer={tokenData.RenewalBuffer.TotalSeconds:F0}s");
    }

    public TokenData? Get(string userEmail) =>
        _tokens.TryGetValue(userEmail.ToLowerInvariant(), out var data) ? data : null;

    public bool HasTokens(string userEmail) =>
        _tokens.ContainsKey(userEmail.ToLowerInvariant());

    public void Remove(string userEmail)
    {
        _tokens.TryRemove(userEmail.ToLowerInvariant(), out _);
        Console.WriteLine($"[TOKEN-CACHE] Removed for {userEmail}");
    }
}