using Microsoft.AspNetCore.SignalR.Client;
using Shared;

namespace BlazorApp1.Client.Services;

public class WasmNotificationSubscriber : INotificationSubscriber
{
    private readonly HubConnection _hubConnection;

    public event Action<WarehouseBookingDTO>? OnMessageReceived;

    public WasmNotificationSubscriber(string hubUrl)
    {
        _hubConnection = new HubConnectionBuilder()
            .WithUrl(hubUrl)
            .WithAutomaticReconnect()
            .Build();

        _hubConnection.On<WarehouseBookingDTO>("ReceiveMessage", msg =>
        {
            OnMessageReceived?.Invoke(msg);
        });
    }

    public async Task StartAsync()
    {
        await _hubConnection.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _hubConnection.DisposeAsync();
    }
}