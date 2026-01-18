using BlazorApp1.Client.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Shared;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddScoped<INotificationSubscriber>(sp =>
{
    var nav = sp.GetRequiredService<NavigationManager>();
    var hubUrl = nav.ToAbsoluteUri("/notificationhub").ToString();
    return new WasmNotificationSubscriber(hubUrl);
});

await builder.Build().RunAsync();