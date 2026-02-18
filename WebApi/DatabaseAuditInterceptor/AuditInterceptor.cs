using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using WebApi.Models;

namespace WebApi.DatabaseAuditInterceptor;

/// <summary>
/// Intercepts SaveChanges to automatically create audit records
/// for any entity implementing IAuditable&lt;T&gt;.
/// 
/// Two-phase approach:
///   Phase 1 (before save): Capture Updates and Deletes (we have the data now)
///   Phase 2 (after save):  Capture Creates (we need the DB-generated Id)
/// </summary>
public class AuditInterceptor(IHttpContextAccessor httpContextAccessor) : SaveChangesInterceptor
{
    // Holds audit records from Phase 1 until we can save them in Phase 2
    private readonly List<AuditBase> _pendingAudits = [];

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is null) return base.SavingChangesAsync(eventData, result, cancellationToken);

        var tracker = eventData.Context.ChangeTracker;
        var userId = httpContextAccessor.HttpContext?.User
            .FindFirst("sub")?.Value ?? "system";

        _pendingAudits.Clear();

        foreach (var entry in tracker.Entries())
        {
            // Check if entity implements IAuditable<T> for any T
            var auditableInterface = entry.Entity.GetType()
                .GetInterfaces()
                .FirstOrDefault(i => i.IsGenericType
                    && i.GetGenericTypeDefinition() == typeof(IAuditable<>));

            if (auditableInterface is null) continue;

            AuditType? auditType = entry.State switch
            {
                EntityState.Added => AuditType.Create,
                EntityState.Modified => AuditType.Update,
                EntityState.Deleted => AuditType.Delete,
                _ => null
            };

            if (auditType is null) continue;

            // Call ToAudit() via the interface
            var toAuditMethod = auditableInterface.GetMethod(nameof(IAuditable<AuditBase>.ToAudit))!;
            var audit = (AuditBase)toAuditMethod.Invoke(entry.Entity, null)!;

            audit.AuditType = auditType.Value;
            audit.AuditTimestamp = DateTimeOffset.UtcNow;
            audit.AuditUserId = userId;

            if (auditType == AuditType.Create)
            {
                // Phase 2: Need DB-generated ID, so defer
                _pendingAudits.Add(audit);
            }
            else
            {
                // Phase 1: Update/Delete — data is available now, add directly
                eventData.Context.Add(audit);
            }
        }

        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default)
    {
        // Phase 2: Now DB-generated keys exist, save the Create audits
        if (_pendingAudits.Count > 0 && eventData.Context is not null)
        {
            // Re-read EntityId from the now-saved entities for Creates
            foreach (var entry in eventData.Context.ChangeTracker.Entries())
            {
                var auditableInterface = entry.Entity.GetType()
                    .GetInterfaces()
                    .FirstOrDefault(i => i.IsGenericType
                        && i.GetGenericTypeDefinition() == typeof(IAuditable<>));

                if (auditableInterface is null) continue;

                // Re-snapshot with the real ID
                var toAuditMethod = auditableInterface.GetMethod(nameof(IAuditable<AuditBase>.ToAudit))!;
                var freshAudit = (AuditBase)toAuditMethod.Invoke(entry.Entity, null)!;

                // Find the matching pending audit and update its EntityId
                var pending = _pendingAudits
                    .FirstOrDefault(a => a.GetType() == freshAudit.GetType()
                        && a.EntityId == "0"); // default long.ToString()

                if (pending is not null)
                    pending.EntityId = freshAudit.EntityId;
            }

            eventData.Context.AddRange(_pendingAudits);
            _pendingAudits.Clear();

            await eventData.Context.SaveChangesAsync(cancellationToken);
        }

        return await base.SavedChangesAsync(eventData, result, cancellationToken);
    }
}