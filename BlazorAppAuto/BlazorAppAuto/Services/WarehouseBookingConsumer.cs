using BlazorAppAuto.Hubs;
using MassTransit;
using Microsoft.AspNetCore.SignalR;
using Shared;

namespace BlazorAppAuto.Services;

public class WarehouseBookingConsumer(IHubContext<NotificationHub> hubContext) : IConsumer<WarehouseBookingDTO>
{
    public async Task Consume(ConsumeContext<WarehouseBookingDTO> context)
    {
        await hubContext.Clients.All.SendAsync("ReceiveMessage", context.Message);
    }
}