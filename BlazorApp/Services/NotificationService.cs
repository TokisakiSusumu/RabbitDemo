using Shared;

namespace BlazorApp.Services;

public class NotificationService
{
    public List<NotificationMessage> Messages { get; } = [];
    public event Action? OnChange;

    public void Add(NotificationMessage message)
    {
        Messages.Insert(0, message);
        OnChange?.Invoke();
    }
}
