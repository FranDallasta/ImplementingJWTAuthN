using ImplementingJWTAuthN.Data;
using Microsoft.EntityFrameworkCore;
using ImplementingJWTAuthN.Models;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using dotenv.net;

var builder = WebApplication.CreateBuilder(args);

DotEnv.Load();

var jwtKey = Environment.GetEnvironmentVariable("Jwt__Key")
             ?? throw new InvalidOperationException("JWT Key is missing.");
var issuer = Environment.GetEnvironmentVariable("Jwt__Issuer")
             ?? throw new InvalidOperationException("JWT Issuer is missing.");
var audience = Environment.GetEnvironmentVariable("Jwt__Audience")
               ?? throw new InvalidOperationException("JWT Audience is missing.");
var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
                       ?? throw new InvalidOperationException("Default connection string is missing.");

// Add services
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });


builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("StudentPolicy", policy => policy.RequireRole("Student"));
    options.AddPolicy("InstructorPolicy", policy => policy.RequireRole("Instructor"));
});

var app = builder.Build();

// Middleware
app.UseAuthentication();
app.UseAuthorization();

// /register endpoint
app.MapPost("/register", async (User user, AppDbContext dbContext) =>
{
    // Check if the email already exists
    if (await dbContext.Users.AnyAsync(u => u.Email == user.Email))
    {
        return Results.Conflict("A user with this email already exists.");
    }

    // Hash the password
    using var sha256 = SHA256.Create();
    var passwordHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(user.PasswordHash));
    user.PasswordHash = Convert.ToBase64String(passwordHash);

    // Add the user to the database
    dbContext.Users.Add(user);
    await dbContext.SaveChangesAsync();

    return Results.Created($"/register/{user.Id}", user);
});

// /login endpoint
app.MapPost("/login", async (LoginRequest loginRequest, AppDbContext dbContext) =>
{
    // Find the user by email
    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Email == loginRequest.Email);
    if (user == null)
    {
        return Results.NotFound("Invalid email or password.");
    }

    // Verify the password
    using var sha256 = SHA256.Create();
    var passwordHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(loginRequest.Password));
    var hashedPassword = Convert.ToBase64String(passwordHash);

    if (user.PasswordHash != hashedPassword)
    {
        return Results.Unauthorized();
    }

    // Generate JWT
    var jwtKeyString = jwtKey;
    
    if (string.IsNullOrEmpty(jwtKeyString))
    {
        throw new InvalidOperationException("JWT Key is not configured in appsettings.json.");
    }
    var jwtKeyFinal = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKeyString));
    var credentials = new SigningCredentials(jwtKeyFinal, SecurityAlgorithms.HmacSha256);
    var claims = new[]
    {
        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, user.Email),
        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, user.Role)
    };

    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: credentials
    );

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { Token = tokenString });
});

app.MapGet("/secure/upload-grades", async (AppDbContext dbContext, HttpContext httpContext) =>
{

    var email = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

    if (string.IsNullOrEmpty(email))
    {
        return Results.Unauthorized();
    }

    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Email == email);
    if (user == null)
    {
        return Results.NotFound("User not found.");
    }

    return Results.Ok($"Grades uploaded successfully by {user.FullName} ({user.Role}).");
}).RequireAuthorization("InstructorPolicy");

// Secure endpoint for students
app.MapGet("/secure/view-grades", async (AppDbContext dbContext, HttpContext httpContext) =>
{
    var email = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
    var role = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

    if (string.IsNullOrEmpty(email))
    {
        Console.WriteLine("Token validation failed. Email is null or empty.");
        return Results.Unauthorized();
    }

    Console.WriteLine($"Token validated. Email: {email}, Role: {role}");

    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Email == email);
    if (user == null)
    {
        Console.WriteLine($"User with email {email} not found.");
        return Results.NotFound("User not found.");
    }

    return Results.Ok($"Grades viewed successfully by {user.FullName} ({user.Role}).");
}).RequireAuthorization("StudentPolicy");


app.Run();