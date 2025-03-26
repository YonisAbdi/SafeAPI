using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SecureAPIApp.Data;
using Microsoft.AspNetCore.Identity.UI.Services;
using SecureAPI.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Konfigurera databas med retry-logik
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlServerOptions => sqlServerOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(10),
            errorNumbersToAdd: null
        )));

// 2. Konfigurera Identity med 2FA-stöd
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true; // Kräv bekräftat konto
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider; // Aktivera TOTP
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddTokenProvider<EmailTokenProvider<IdentityUser>>("email"); // För e-postbaserad 2FA

// 3. Konfigurera token-leverantörer för 2FA
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(15); // Livstid för 2FA-koder
});

// 4. Konfigurera JWT-autentisering
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

// 5. Lägg till e-posttjänst för 2FA (mockad här, ersätt med riktig implementering)
builder.Services.AddSingleton<IEmailSender, DummyEmailSender>();

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

// 6. Temporär e-posttjänst för demoändamål
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