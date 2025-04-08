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
using Microsoft.AspNetCore.Authorization;

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

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&code={WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token))}";

        await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

        return Ok(new { message = "Registration successful. Please check your email to confirm your account." });
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
            return Unauthorized("Email not confirmed");

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your code is: {token}");
            return Ok(new { Requires2FA = true, UserId = user.Id });
        }

        var jwtToken = GenerateJwtToken(user);
        return Ok(new { Token = jwtToken });
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> Verify2Fa([FromBody] Verify2FaModel model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null) return NotFound("User not found");

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, model.Code);
        if (!isValid) return Unauthorized("Invalid code");

        var jwtToken = GenerateJwtToken(user);
        return Ok(new { Token = jwtToken });
    }

    [HttpPost("enable-2fa-email")]
    [Authorize]
    public async Task<IActionResult> Enable2FaEmail()
    {
        var userName = User.Identity?.Name;

        if (string.IsNullOrEmpty(userName))
        {
            _logger.LogWarning(" JWT does not contain a user name.");
            return Unauthorized("Invalid token");
        }

        var user = await _userManager.FindByNameAsync(userName);

        if (user == null)
        {
            _logger.LogWarning(" User not found by username: {UserName}", userName);
            return NotFound("User not found");
        }

        var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
        await _emailSender.SendEmailAsync(user.Email, "Enable 2FA", $"Use this code to enable 2FA: {token}");

        return Ok(new { message = "2FA token sent to email." });
    }


    [HttpPost("confirm-2fa-email")]
    [Authorize]
    public async Task<IActionResult> Confirm2FaEmail([FromBody] Confirm2FaEmailModel model)
    {
        var userName = User.Identity?.Name;

        if (string.IsNullOrEmpty(userName))
        {
            _logger.LogWarning(" JWT does not contain a username (sub claim).");
            return Unauthorized("Invalid token");
        }

        var user = await _userManager.FindByNameAsync(userName);

        if (user == null)
        {
            _logger.LogWarning(" User not found by username: {UserName}", userName);
            return NotFound("User not found");
        }

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            TokenOptions.DefaultEmailProvider,
            model.Code
        );

        if (!isValid)
        {
            _logger.LogWarning(" Invalid 2FA code for user: {UserName}", userName);
            return BadRequest("Invalid verification code");
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        return Ok(new { message = "2FA via email enabled successfully." });
    }


    private string GenerateJwtToken(AppUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };

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
