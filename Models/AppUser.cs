using Microsoft.AspNetCore.Identity;

namespace SecureAPI.Models
{
    public class AppUser : IdentityUser
    {
        public string? TwoFactorSecret { get; set; }

        public bool IsApproved { get; set; } = false;
    }
}
