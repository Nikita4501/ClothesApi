using System.Text.Json.Serialization;
using ClothesApi.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<ClothesApiContext>();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});
var key = new SymmetricSecurityKey(
    RandomNumberGenerator.GetBytes(32));

var validation = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "ClothesApi",

    ValidateAudience = true,
    ValidAudience = "ClothesApiClient",

    ValidateIssuerSigningKey = true,
    IssuerSigningKey = key,

    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,

    NameClaimType = "name",
    RoleClaimType = "role"
};

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = validation;
    });

builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/register", async (RegisterRequest request, ClothesApiContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Login == request.Login))
        return Results.Conflict("Пользователь с таким логином уже существует");

    var user = new User
    {
        Login = request.Login,
        Phone = request.Phone,
        DeliveryAddress = request.DeliveryAddress,
        Role = "User"
    };
    user.PasswordHash = new PasswordHasher<User>().HashPassword(user, request.Password);

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Login, user.Role });
}).AllowAnonymous();

app.MapPost("/api/auth/login", async (LoginRequest request, ClothesApiContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(
        u => u.Login == request.Login);

    if (user == null ||
        string.IsNullOrWhiteSpace(request.Password))
        return Results.Challenge();

    var hasher = new PasswordHasher<User>();
    var result = hasher.VerifyHashedPassword(
        user, user.PasswordHash, request.Password);

    if (result == PasswordVerificationResult.Failed)
        return Results.Challenge();

    return Results.Ok(new
    {
        access_token = CreateToken(user),
        token_type = "Bearer"
    });
}).AllowAnonymous();

app.MapGet("/api/clothes", async (ClothesApiContext db) =>
    await db.ClothingItems.Include(c => c.ClothingSizes).ToListAsync());

app.MapGet("/api/clothes/search", async (string name, ClothesApiContext db) =>
    await db.ClothingItems
        .Include(c => c.ClothingSizes)
        .Where(c => EF.Functions.Like(c.Name, $"%{name}%"))
        .ToListAsync());

app.MapPost("/api/orders", async (CreateOrderRequest request, ClothesApiContext db, ClaimsPrincipal user) =>
{
    var userId = int.Parse(user.FindFirst("sub")!.Value);
    var order = new Order { UserId = userId, CreatedAt = DateTime.UtcNow, Status = OrderStatus.New };

    foreach (var item in request.Items)
    {
        var size = await db.ClothingSizes
            .Include(s => s.ClothingItem)
            .FirstOrDefaultAsync(s => s.Id == item.ClothingSizeId && s.ClothingItemId == item.ClothingItemId);

        if (size is null)
            return Results.BadRequest($"Товар {item.ClothingItemId} с размером {item.ClothingSizeId} не найден");
        if (!size.ClothingItem.IsAvailableForSale)
            return Results.BadRequest($"Товар «{size.ClothingItem.Name}» снят с продажи");
        if (size.Stock < item.Quantity)
            return Results.BadRequest($"Недостаточно товара «{size.ClothingItem.Name}» размера {size.LetterSize}: в наличии {size.Stock}");

        size.Stock -= item.Quantity;
        size.ClothingItem.PurchaseCount += item.Quantity;

        order.OrderItems.Add(new OrderItem
        {
            ClothingItemId = item.ClothingItemId,
            ClothingSizeId = item.ClothingSizeId,
            Quantity = item.Quantity
        });
    }

    db.Orders.Add(order);
    await db.SaveChangesAsync();
    return Results.Created($"/api/orders/{order.Id}", order);
}).RequireAuthorization();

app.MapGet("/api/orders/status/{status}", async (string status, ClothesApiContext db) =>
    await db.Orders
        .Where(o => o.Status == status)
        .Include(o => o.User)
        .Include(o => o.OrderItems).ThenInclude(i => i.ClothingItem)
        .Include(o => o.OrderItems).ThenInclude(i => i.ClothingSize)
        .ToListAsync())
    .RequireAuthorization();

app.MapGet("/api/orders/user/{userId:int}", async (int userId, ClothesApiContext db, ClaimsPrincipal user) =>
{
    var currentUserId = int.Parse(user.FindFirst("sub")!.Value);
    if (!user.IsInRole("Manager") && userId != currentUserId)
        return Results.Forbid();

    return Results.Ok(await db.Orders
        .Where(o => o.UserId == userId)
        .Include(o => o.OrderItems).ThenInclude(i => i.ClothingItem)
        .Include(o => o.OrderItems).ThenInclude(i => i.ClothingSize)
        .ToListAsync());
}).RequireAuthorization();

app.MapPatch("/api/orders/{id:int}/status", async (int id, ChangeStatusRequest request, ClothesApiContext db) =>
{
    var order = await db.Orders.FindAsync(id);
    if (order is null) return Results.NotFound();

    var allowed = new[] { OrderStatus.New, OrderStatus.Processing, OrderStatus.Shipped, OrderStatus.Delivered, OrderStatus.Cancelled };
    if (!allowed.Contains(request.Status))
        return Results.BadRequest("Недопустимый статус");

    order.Status = request.Status;
    await db.SaveChangesAsync();
    return Results.Ok(order);
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPatch("/api/sizes/{id:int}/stock", async (int id, ChangeStockRequest request, ClothesApiContext db) =>
{
    var size = await db.ClothingSizes.FindAsync(id);
    if (size is null) return Results.NotFound();

    size.Stock = request.Stock;
    await db.SaveChangesAsync();
    return Results.Ok(size);
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPatch("/api/clothes/{id:int}/remove-from-sale", async (int id, ClothesApiContext db) =>
{
    var item = await db.ClothingItems.FindAsync(id);
    if (item is null) return Results.NotFound();

    item.IsAvailableForSale = false;
    await db.SaveChangesAsync();
    return Results.Ok(item);
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.MapPatch("/api/clothes/{id:int}/restore", async (int id, ClothesApiContext db) =>
{
    var item = await db.ClothingItems.FindAsync(id);
    if (item is null) return Results.NotFound();

    item.IsAvailableForSale = true;
    await db.SaveChangesAsync();
    return Results.Ok(item);
}).RequireAuthorization(policy => policy.RequireAuthenticatedUser().RequireRole("Manager"));

app.Run();
string CreateToken(User user)
{
    var claims = new[]
    {
        new Claim("sub", user.Id.ToString()),
        new Claim("name", user.Login),
        new Claim("role", user.Role)
    };

    var token = new JwtSecurityToken(
        issuer: "ClothesApi",
        audience: "ClothesApiClient",
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(15),
        signingCredentials: new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256));

    return new JwtSecurityTokenHandler().WriteToken(token);
}

public record RegisterRequest(string Login, string Password, string Phone, string DeliveryAddress);
public record LoginRequest(string Login, string Password);
public static class OrderStatus
{
    public const string New = "Новый";
    public const string Processing = "В обработке";
    public const string Shipped = "Отправлен";
    public const string Delivered = "Доставлен";
    public const string Cancelled = "Отменён";
}

public record CreateOrderRequest(List<OrderItemDto> Items);
public record OrderItemDto(int ClothingItemId, int ClothingSizeId, int Quantity);
public record ChangeStatusRequest(string Status);
public record ChangeStockRequest(int Stock);