using MassTransit;
using Shared;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMassTransit(x =>
{
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host("localhost", "/", h =>
        {
            h.Username("guest");
            h.Password("guest");
        });
    });
});

var app = builder.Build();

app.MapPost("/notify", async (IPublishEndpoint publisher, NotificationRequest request) =>
{
    await publisher.Publish(new NotificationMessage(request.Content, DateTime.UtcNow));
    return Results.Ok("Published");
});

app.Run();

public record NotificationRequest(string Content);
