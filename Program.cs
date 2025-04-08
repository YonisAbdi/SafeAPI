using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Security.Claims;
using SecureAPI.Models;           // AppUser
using SecureAPI.Services;        // EmailSender
using SecureAPI.Settings;        // EmailSettings
using SecureAPIApp.Data;         // ApplicationDbContext

var builder = WebApplication.CreateBuilder(args);

// 1. Bind EmailSettings from appsettings.json
builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("Email"));

// 2. Add DbContext with retry logic
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions => sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(10),
            errorNumbersToAdd: null
        )));

// 3. Add Identity + 2FA
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddTokenProvider<EmailTokenProvider<AppUser>>(TokenOptions.DefaultEmailProvider);

// 4. Configure token lifespan for 2FA
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(10);
});

// 5. Add JWT Authentication
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
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])
        ),
        NameClaimType = ClaimTypes.NameIdentifier
    };
});

// 6. Register EmailSender
builder.Services.AddTransient<IEmailSender, EmailSender>();

// 7. Add controllers + authorization
builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

// 8. Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
    await next();
});

// 9. Routing + Auth
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// 10. Map controller endpoints
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();

    foreach (var ep in endpoints.DataSources.SelectMany(ds => ds.Endpoints))
    {
        Console.WriteLine($" Mapped endpoint: {ep.DisplayName}");
    }
});

app.Run();
