using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SecureAPIApp.Data;
using SecureAPI.Models;
using IEmailSender = SecureAPI.Models.IEmailSender;

var builder = WebApplication.CreateBuilder(args);

// 1. Databaskoppling med retry-logik
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlServerOptions => sqlServerOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(10),
            errorNumbersToAdd: null // Anger namnet så det kompilerar korrekt
        )));

// 2. Identity med e-postbaserad 2FA
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddTokenProvider<EmailTokenProvider<IdentityUser>>(TokenOptions.DefaultEmailProvider); // "Email"

// 3. Giltighetstid för 2FA/e-post-tokens
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(10);
});

// 4. JWT-konfiguration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Sätt till true i produktion
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

// 5. E-posttjänst – ersätt med riktig SMTP- eller API-baserad tjänst i produktion
builder.Services.AddSingleton<IEmailSender, DummyEmailSender>();

// 6. Grundläggande tjänster
builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

// 7. Middleware pipeline
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

// 8. Mockad e-posttjänst (visar bara meddelandet i konsolen)
public class DummyEmailSender : IEmailSender
{
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        Console.WriteLine($"Skickar e-post till: {email}");
        Console.WriteLine($"Ämne: {subject}");
        Console.WriteLine($"Meddelande: {htmlMessage}");


        return Task.CompletedTask;
    }
}
