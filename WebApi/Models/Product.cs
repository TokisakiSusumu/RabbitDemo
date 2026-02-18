using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApi.Models;

[Table(nameof(Product))]
public record Product : IAuditable<Adt_Product>
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [MaxLength(200)]
    public required string Name { get; set; }

    [Column(TypeName = "decimal(18,2)")]
    public required decimal Price { get; set; }

    public required int QuantityInStock { get; set; }

    [MaxLength(100)]
    public required string Category { get; set; }

    public bool IsActive { get; set; } = true;

    public Adt_Product ToAudit() => new()
    {
        EntityId = Id.ToString(),
        AuditType = default, // Set by interceptor
        Name = Name,
        Price = Price,
        QuantityInStock = QuantityInStock,
        Category = Category,
        IsActive = IsActive
    };
}
