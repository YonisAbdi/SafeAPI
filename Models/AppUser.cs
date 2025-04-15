using Microsoft.AspNetCore.Identity;

namespace SecureAPI.Models
{
    public class AppUser : IdentityUser
    {
        public string? TwoFactorSecret { get; set; }
    }
}
