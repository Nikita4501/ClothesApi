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