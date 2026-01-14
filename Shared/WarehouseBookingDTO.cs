namespace Shared;

public record WarehouseBookingDTO(
    string Content,
    DateTime Timestamp,
    MessagePayload? Payload = null,
    List<string>? Tags = null
);

public record MessagePayload(string Category, int Priority, Dictionary<string, object>? Data = null);