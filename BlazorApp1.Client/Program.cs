using BlazorApp1.Client;
using BlazorApp1.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

Console.WriteLine(">>> [WASM] Program.cs: Starting WebAssembly app...");

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Auth services for WASM
builder.Services.AddAuthorizationCore();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddSingleton<AuthenticationStateProvider, PersistentAuthStateProvider>();

Console.WriteLine(">>> [WASM] Program.cs: Services registered, running app...");

await builder.Build().RunAsync();
