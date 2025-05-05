using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using SecureAPI.Models;

namespace SecureAPI.Controllers
{
    [ApiController]
    [Route("api/admin")]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEmailSender _emailSender;

        public AdminController(UserManager<AppUser> userManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        [HttpGet("pending-users")]
        public async Task<IActionResult> GetPendingUsers()
        {
            var users = await _userManager.Users
                .Where(u => !u.EmailConfirmed)
                .Select(u => new { u.Id, u.Email })
                .ToListAsync();

            return Ok(users);
        }

        [HttpPost("confirm-user")]
        public async Task<IActionResult> ConfirmUser([FromBody] string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("Användare hittades inte");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
                return BadRequest("Kunde inte bekräfta användaren.");

            // Skicka inloggningslänk
            var loginUrl = "http://localhost:5173/login"; // Anpassa efter Cloudflare eller produktion
            await _emailSender.SendEmailAsync(
                user.Email,
                "Ditt konto är nu godkänt",
                $"Hej! Din registrering har godkänts av en administratör.<br>" +
                $"Du kan nu logga in via följande länk: <a href='{loginUrl}'>{loginUrl}</a>"
            );

            // Generera och skicka 2FA-kod direkt
            var twoFaCode = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendEmailAsync(
                user.Email,
                "Aktivera tvåfaktorsautentisering (2FA)",
                $"För att aktivera 2FA, använd denna kod: <strong>{twoFaCode}</strong>"
            );

            return Ok("Användaren har bekräftats och fått inloggnings- och 2FA-mejl.");
        }


    }
}
