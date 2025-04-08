using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using SecureAPI.Settings;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace SecureAPI.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailSettings _settings;

        public EmailSender(IOptions<EmailSettings> settings)
        {
            _settings = settings.Value;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var smtpClient = new SmtpClient(_settings.SmtpHost)
            {
                Port = _settings.SmtpPort,
                Credentials = new NetworkCredential(_settings.Username, _settings.Password),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_settings.From),
                Subject = subject,
                Body = htmlMessage,
                IsBodyHtml = true
            };

            mailMessage.To.Add(email);
            return smtpClient.SendMailAsync(mailMessage);
        }
    }
}
