using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public enum EmailChangeResult
  {
    Success,
    InvalidPassword,
    EmailInUse,
    SameEmail,
    Failed
  }

  public interface IEmailChangeService
  {
    Task<EmailChangeResult> RequestEmailChangeAsync(AppUser user, string newEmail, string password);
    Task<bool> ConfirmEmailChangeAsync(AppUser user, string newEmail, string token);
  }
}