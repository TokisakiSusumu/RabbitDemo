using BlazorApp1.Components;
using BlazorApp1.Hubs;
using BlazorApp1.Services;
using MassTransit;
using Microsoft.AspNetCore.Components.Authorization;
using Shared;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options =>
    {
        options.DetailedErrors = true;
    })
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddSignalR();

// Existing services
builder.Services.AddSingleton<NotificationService>();
builder.Services.AddScoped<INotificationSubscriber, ServerNotificationSubscriber>();

// Auth services
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("http://localhost:5100") });
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();
builder.Services.AddCascadingAuthenticationState();  // <-- ADD THIS LINE
builder.Services.AddAuthorizationCore();

// MassTransit (existing)
builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<WarehouseBookingConsumer>();
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host("localhost", "/", h =>
        {
            h.Username("guest");
            h.Password("guest");
        });
        cfg.ConfigureEndpoints(context);
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapHub<NotificationHub>("/notificationhub");

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(BlazorApp1.Client._Imports).Assembly);

app.Run();