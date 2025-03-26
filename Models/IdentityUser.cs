using Microsoft.AspNetCore.Identity;

namespace SecureAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public bool TwoFactorEnabled { get; set; }
        public string? TwoFactorSecret { get; set; } // För TOTP
        public string? PhoneNumberConfirmed { get; set; } // För SMS
    }
}
