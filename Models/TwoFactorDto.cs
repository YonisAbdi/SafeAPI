namespace SecureAPI.Models
{
    public class Confirm2FaEmailModel
    {
        public string UserId { get; set; }
        public string Code { get; set; }
    }
}
