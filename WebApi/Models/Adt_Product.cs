namespace WebApi.Models;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

/// <summary>
/// Mirror of Product: same fields, no navigation properties.
/// </summary>
[Table(nameof(Adt_Product))]
public record Adt_Product : AuditBase
{
    [MaxLength(200)]
    public required string Name { get; set; }

    [Column(TypeName = "decimal(18,2)")]
    public decimal Price { get; set; }

    public int QuantityInStock { get; set; }

    [MaxLength(100)]
    public required string Category { get; set; }

    public bool IsActive { get; set; }
}