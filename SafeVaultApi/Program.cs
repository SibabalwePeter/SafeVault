using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BCrypt.Net;

// -----------------------------
// Builder setup
// -----------------------------
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "SafeVault",
            ValidAudience = "SafeVaultUsers",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SuperSecretKey12345"))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// -----------------------------
// In-memory user store
// (replace with DB later)
// -----------------------------
var users = new List<(string Username, string PasswordHash, string Role)>
{
    ("admin", BCrypt.Net.BCrypt.HashPassword("AdminPass123"), "admin"),
    ("user", BCrypt.Net.BCrypt.HashPassword("UserPass123"), "user")
};

// -----------------------------
// Authentication: Login endpoint
// -----------------------------
app.MapPost("/login", (string username, string password) =>
{
    var user = users.FirstOrDefault(u => u.Username == username);

    if (user == default || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes("SuperSecretKey12345");

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("username", user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = "SafeVault",
        Audience = "SafeVaultUsers",
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    var jwt = tokenHandler.WriteToken(token);

    return Results.Ok(new { Token = jwt });
});

// -----------------------------
// Authorization-protected endpoints
// -----------------------------
app.MapGet("/dashboard", () => "Welcome to SafeVault Dashboard!")
    .RequireAuthorization();

app.MapGet("/admin", () => "Welcome Admin! Here are the sensitive logs...")
    .RequireAuthorization(policy => policy.RequireRole("admin"));

// -----------------------------
// Input validation route
// -----------------------------
app.MapPost("/submit", (string username, string email) =>
{
    var cleanUsername = InputValidator.SanitizeUsername(username);
    var cleanEmail = InputValidator.SanitizeEmail(email);

    if (string.IsNullOrEmpty(cleanUsername) || string.IsNullOrEmpty(cleanEmail))
        return Results.BadRequest("Invalid input provided.");

    return Results.Ok(new { Username = cleanUsername, Email = cleanEmail });
});

app.Run();


// -----------------------------
// Helper class (must be AFTER top-level code)
// -----------------------------
static class InputValidator
{
    public static string SanitizeUsername(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return Regex.Replace(input, @"[^a-zA-Z0-9_.]", "");
    }

    public static string SanitizeEmail(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
        return Regex.IsMatch(input, emailPattern) ? input : string.Empty;
    }
}
