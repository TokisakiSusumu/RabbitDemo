namespace WebApi.Models;

/// <summary>
/// Implement this on any entity you want audited.
/// TAudit is the mirror audit record type.
/// </summary>
public interface IAuditable<TAudit> where TAudit : AuditBase
{
    /// <summary>
    /// Maps current entity state into a new audit record (mirror snapshot).
    /// </summary>
    TAudit ToAudit();
}
