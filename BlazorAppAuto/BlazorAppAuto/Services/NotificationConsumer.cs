using MassTransit;
using Microsoft.AspNetCore.SignalR;
using BlazorAppAuto.Hubs;
using Shared;

namespace BlazorAppAuto.Services;

public class NotificationConsumer(IHubContext<NotificationHub> hubContext) : IConsumer<NotificationMessage>
{
    public async Task Consume(ConsumeContext<NotificationMessage> context)
    {
        await hubContext.Clients.All.SendAsync("ReceiveNotification", context.Message);
    }
}