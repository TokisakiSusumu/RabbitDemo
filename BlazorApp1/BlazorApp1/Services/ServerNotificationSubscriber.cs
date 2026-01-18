using Shared;

namespace BlazorApp1.Services;

public class ServerNotificationSubscriber : INotificationSubscriber
{
    private readonly NotificationService _notificationService;

    public event Action<WarehouseBookingDTO>? OnMessageReceived;

    public ServerNotificationSubscriber(NotificationService notificationService)
    {
        _notificationService = notificationService;
    }

    public Task StartAsync()
    {
        _notificationService.OnMessageReceived += HandleMessage;
        return Task.CompletedTask;
    }

    private void HandleMessage(WarehouseBookingDTO message)
    {
        OnMessageReceived?.Invoke(message);
    }

    public ValueTask DisposeAsync()
    {
        _notificationService.OnMessageReceived -= HandleMessage;
        return ValueTask.CompletedTask;
    }
}