using MassTransit;
using Shared;

namespace BlazorApp.Services;

public class NotificationConsumer(NotificationService notificationService) : IConsumer<NotificationMessage>
{
    public Task Consume(ConsumeContext<NotificationMessage> context)
    {
        notificationService.Add(context.Message);
        return Task.CompletedTask;
    }
}
