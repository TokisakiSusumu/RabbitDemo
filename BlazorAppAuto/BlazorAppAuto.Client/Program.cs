using BlazorAppAuto.Client;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Shared;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
await builder.Build().RunAsync();
