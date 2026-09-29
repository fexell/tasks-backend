

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface IVerificationEmailService
  {
    Task<bool> SendVerificationEmailAsync(AppUser user);
    Task<(bool Sent, TimeSpan? RetryAfter)> TryResendVerificationEmailAsync(AppUser user);
  }
}