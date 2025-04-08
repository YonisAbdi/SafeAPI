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
using Microsoft.AspNetCore.Identity.UI.Services;
using IEmailSender = SecureAPI.Models.IEmailSender;
using SecureAPI.DTO_modell;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;
    private readonly IEmailSender _emailSender;

    public AuthController(
        UserManager<IdentityUser> userManager,
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
        if (model == null)
        {
            _logger.LogWarning("Register request received with null model.");
            return BadRequest("Invalid request data");
        }

        var user = new IdentityUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} registered successfully.", model.Email);

            // Generera e-postbekräftelse
            var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&code={WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(emailToken))}";

            await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            return Ok(new { message = "User registered successfully. Please check your email for verification." });
        }

        foreach (var error in result.Errors)
        {
            _logger.LogError("Registration error for {Email}: {ErrorDescription}", model.Email, error.Description);
        }

        return BadRequest(result.Errors);
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (userId == null || code == null)
        {
            return BadRequest("Invalid email confirmation link");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{userId}'.");
        }

        var decodedCode = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        var result = await _userManager.ConfirmEmailAsync(user, decodedCode);

        if (!result.Succeeded)
        {
            return BadRequest("Error confirming your email.");
        }

        return Ok("Thank you for confirming your email.");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (model == null)
        {
            _logger.LogWarning("Login request received with null model.");
            return BadRequest("Invalid request data");
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            _logger.LogWarning("Login failed for {Email} - user not found.", model.Email);
            return Unauthorized("Invalid credentials");
        }

        // Kräv e-postbekräftelse
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized("Email not confirmed");
        }

        if (!await _userManager.CheckPasswordAsync(user, model.Password))
        {
            _logger.LogWarning("Login failed for {Email} - invalid password.", model.Email);
            return Unauthorized("Invalid credentials");
        }

        // Kolla om 2FA är aktiverat
        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            // Generera och skicka 2FA-kod
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your verification code is: {token}");

            return Ok(new { Requires2FA = true, UserId = user.Id });
        }

        // Generera JWT-token om 2FA inte krävs
        var jwtToken = GenerateJwtToken(user);
        return Ok(new { Token = jwtToken });
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> Verify2Fa([FromBody] Verify2FaModel model)
    {
        if (model == null)
        {
            return BadRequest("Invalid request data");
        }

        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound("User not found");
        }

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        TokenOptions.DefaultEmailProvider,
        model.Code);


        if (!isValid)
        {
            return Unauthorized("Invalid verification code");
        }

        // Generera JWT-token efter lyckad 2FA-verifiering
        var jwtToken = GenerateJwtToken(user);
        return Ok(new { Token = jwtToken });
    }

    [HttpPost("enable-2fa-email")]
    [Authorize]
    public async Task<IActionResult> Enable2FaEmail()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound("User not found");

        var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

        await _emailSender.SendEmailAsync(user.Email, "2FA Email Setup",
            $"Use this code to verify 2FA setup: {token}");

        return Ok(new { message = "2FA token sent to email." });
    }

    [HttpPost("confirm-2fa-email")]
    [Authorize]
    public async Task<IActionResult> Confirm2FaEmail([FromBody] Confirm2FaEmailModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound("User not found");

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, model.Code);
        if (!isValid) return BadRequest("Invalid code");

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        return Ok(new { message = "2FA via email enabled successfully." });
    }


    private string GenerateJwtToken(IdentityUser user)
    {
        var jwtKey = _configuration["Jwt:Key"];
        if (string.IsNullOrEmpty(jwtKey))
        {
            _logger.LogError("JWT Key is missing from configuration!");
            throw new Exception("JWT Key is missing from configuration");
        }

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

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
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}