using MassTransit;
using Shared;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMassTransit(x =>
{
    x.UsingRabbitMq((_, cfg) => cfg.Host("localhost", "/", h =>
    {
        h.Username("guest");
        h.Password("guest");
    }));
});

var app = builder.Build();

app.MapPost("/notify", async (IPublishEndpoint publisher, NotificationRequest req) =>
{
    await publisher.Publish(new NotificationMessage(
        req.Content,
        DateTime.UtcNow,
        req.Payload,
        req.Tags
    ));
    return Results.Ok("Published");
});

app.Run();

public record NotificationRequest(
    string Content,
    MessagePayload? Payload = null,
    List<string>? Tags = null
);