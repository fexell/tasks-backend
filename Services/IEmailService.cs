

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface IEmailService
  {
    Task SendAsync(string to, string subject, string htmlBody);
  }
}
