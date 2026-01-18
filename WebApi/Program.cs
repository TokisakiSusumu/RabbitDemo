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
    await publisher.Publish(new WarehouseBookingDTO
    {
        Content = req.Content,
        Timestamp = DateTime.UtcNow,
        Payload = req.Payload,
        Tags = req.Tags
    });
    return Results.Ok("Published");
});

app.Run();

public record NotificationRequest
{
    public string Content { get; init; } = string.Empty;
    public MessagePayload? Payload { get; init; }
    public List<string>? Tags { get; init; }
}