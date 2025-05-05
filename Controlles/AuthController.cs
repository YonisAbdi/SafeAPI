using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.WebUtilities;

namespace SecureAPI.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly IEmailSender _emailSender;

        public AuthController(
            UserManager<AppUser> userManager,
            IConfiguration configuration,
            ILogger<AuthController> logger,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _configuration = configuration;
            _logger = logger;
            _emailSender = emailSender;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new AppUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Skicka info till admin istället för till användaren
            var adminEmail = "yonisabdi.jobb@gmail.com";
            await _emailSender.SendEmailAsync(
                adminEmail,
                "Ny registreringsförfrågan",
                $"En ny användare har registrerat sig med e-post: <strong>{model.Email}</strong>.<br>" +
                $"Logga in på adminpanelen för att granska och bekräfta kontot."
            );

            return Ok(new
            {
                message = "Registreringen lyckades. Vänta på att admin godkänner ditt konto."
            });
        }


        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found");

            var decodedCode = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, decodedCode);

            return result.Succeeded ? Ok("Email confirmed.") : BadRequest("Invalid or expired confirmation link.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Invalid credentials");

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                // Skicka mejl till admin här om du vill
                return Unauthorized("Email not confirmed");
            }

            // Om 2FA inte är aktiverat ännu
            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                // Generera kod direkt och skicka till användarens mejl
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                await _emailSender.SendEmailAsync(user.Email, "Aktivera 2FA", $"Din 2FA-kod är: {token}");

                return Ok(new { mustEnable2FA = true, userId = user.Id });
            }

            // Om 2FA ÄR aktiverat – skicka kod
            var twoFaToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendEmailAsync(user.Email, "Ditt 2FA-inloggningskod", $"Kod: {twoFaToken}");

            return Ok(new { requires2FA = true, userId = user.Id });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2Fa([FromBody] Verify2FaModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound("User not found");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                TokenOptions.DefaultEmailProvider,
                model.Code
            );

            if (!isValid) return Unauthorized("Invalid code");

            var jwtToken = GenerateJwtToken(user);
            return Ok(new { token = jwtToken });
        }


        [HttpPost("enable-2fa-email")]
        [Authorize]
        public async Task<IActionResult> Enable2FaEmail()
        {
            var userName = User.Identity?.Name;
            if (string.IsNullOrEmpty(userName)) return Unauthorized("Invalid token");

            var user = await _userManager.FindByNameAsync(userName);
            if (user == null) return NotFound("User not found");

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendEmailAsync(user.Email, "Enable 2FA", $"Use this code to enable 2FA: {token}");

            return Ok(new { message = "2FA token sent to email." });
        }

        [HttpPost("confirm-2fa-email")]
        public async Task<IActionResult> Confirm2FAEmail([FromBody] Confirm2FaEmailModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound("Användare hittades inte");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                TokenOptions.DefaultEmailProvider,
                model.Code
            );

            if (!isValid)
                return Unauthorized("Ogiltig kod");

            // Aktivera 2FA
            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            // Generera JWT-token
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }



        private string GenerateJwtToken(AppUser user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user), "User cannot be null");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Email ?? ""),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id ?? "")
    };

            // Tilldela roll baserat på e-post
            if (!string.IsNullOrEmpty(user.Email) && user.Email == "yonisabdi.jobb@gmail.com")
            {
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.Role, "User"));
            }

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
