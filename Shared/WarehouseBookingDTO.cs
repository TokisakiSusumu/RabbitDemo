namespace Shared;

public record WarehouseBookingDTO
{
    public string Content { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
    public MessagePayload? Payload { get; init; }
    public List<string>? Tags { get; init; }
}

public record MessagePayload
{
    public string Category { get; init; } = string.Empty;
    public int Priority { get; init; }
    public Dictionary<string, object>? Data { get; init; }
}