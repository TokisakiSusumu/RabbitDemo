namespace WebApi.Models;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public abstract record AuditBase
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long AuditId { get; set; }

    public required AuditType AuditType { get; set; }
    public DateTimeOffset AuditTimestamp { get; set; } = DateTimeOffset.UtcNow;

    [MaxLength(450)]
    public string? AuditUserId { get; set; }

    /// <summary>
    /// Stores the original entity's primary key as string for flexibility
    /// </summary>
    [MaxLength(100)]
    public required string EntityId { get; set; }
}

public enum AuditType
{
    Create,
    Update,
    Delete
}