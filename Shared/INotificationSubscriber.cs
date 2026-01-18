namespace Shared;

public interface INotificationSubscriber : IAsyncDisposable
{
    event Action<WarehouseBookingDTO>? OnMessageReceived;
    Task StartAsync();
}