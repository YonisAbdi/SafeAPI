namespace SecureAPI.Services
{
    public class EmailSender : Models.IEmailSender  // Explicit referens
    {
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(ILogger<EmailSender> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string email, string subject, string message)
        {
            _logger.LogInformation($"Would send email to {email} with subject: {subject}");
            // Implementera riktig e-postlogik här
            return Task.CompletedTask;
        }
    }
}