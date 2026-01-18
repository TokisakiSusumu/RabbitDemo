using BlazorApp1.Hubs;
using MassTransit;
using Microsoft.AspNetCore.SignalR;
using Shared;

namespace BlazorApp1.Services;

public class WarehouseBookingConsumer(
    IHubContext<NotificationHub> hubContext,
    NotificationService notificationService) : IConsumer<WarehouseBookingDTO>
{
    public async Task Consume(ConsumeContext<WarehouseBookingDTO> context)
    {
        // For WebAssembly clients (via SignalR)
        await hubContext.Clients.All.SendAsync("ReceiveMessage", context.Message);

        // For Server-side components (via event)
        notificationService.NotifyMessage(context.Message);
    }
}