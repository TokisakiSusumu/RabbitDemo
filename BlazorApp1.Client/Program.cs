using BlazorApp1.Client;
using BlazorApp1.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

Console.WriteLine("[WASM] Starting WebAssembly app...");

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Auth services for WASM
builder.Services.AddAuthorizationCore();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddSingleton<AuthenticationStateProvider, PersistentAuthStateProvider>();

// HttpClient for calling BFF endpoints on Blazor Server (same origin, cookies sent automatically)
builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
});

// WASM API client - calls BFF proxy endpoints
builder.Services.AddScoped<IApiClient, WasmApiClient>();

Console.WriteLine("[WASM] Services registered, running app...");

await builder.Build().RunAsync();
