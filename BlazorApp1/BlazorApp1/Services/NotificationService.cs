using Shared;

namespace BlazorApp1.Services;

public class NotificationService
{
    public event Action<WarehouseBookingDTO>? OnMessageReceived;

    public void NotifyMessage(WarehouseBookingDTO message)
    {
        OnMessageReceived?.Invoke(message);
    }
}