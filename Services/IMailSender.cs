namespace SecureAPI.Services
{
    public interface IMailSender
    {
        Task SendEmailAsync(string email, string subject, string htmlMessage);
    }
}
