using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApi.Data;
using WebApi.Models;

namespace WebApi.Controller;

[ApiController]
[Route("api/[controller]")]
public class ProductsController(ApplicationDbContext db) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Create(ProductDto dto)
    {
        var product = new Product
        {
            Name = dto.Name,
            Price = dto.Price,
            QuantityInStock = dto.QuantityInStock,
            Category = dto.Category
        };

        db.Products.Add(product);
        await db.SaveChangesAsync(); // Interceptor auto-creates audit record

        return Ok(product);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(long id, ProductDto dto)
    {
        var product = await db.Products.FindAsync(id);
        if (product is null) return NotFound();

        product.Name = dto.Name;
        product.Price = dto.Price;
        product.QuantityInStock = dto.QuantityInStock;
        product.Category = dto.Category;

        await db.SaveChangesAsync(); // Interceptor auto-creates audit record
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(long id)
    {
        var product = await db.Products.FindAsync(id);
        if (product is null) return NotFound();

        db.Products.Remove(product);
        await db.SaveChangesAsync(); // Interceptor auto-creates audit record
        return NoContent();
    }

    [HttpGet("{id}/audit")]
    public async Task<IActionResult> GetAuditTrail(long id)
    {
        var trail = await db.Adt_Products
            .Where(a => a.EntityId == id.ToString())
            .OrderByDescending(a => a.AuditTimestamp)
            .ToListAsync();

        return Ok(trail);
    }
}

public record ProductDto(string Name, decimal Price, int QuantityInStock, string Category);