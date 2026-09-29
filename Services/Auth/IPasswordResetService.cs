using Microsoft.AspNetCore.Identity;
using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface IPasswordResetService
  {
    Task<bool> SendPasswordResetEmailAsync(AppUser user);
    Task<IdentityResult> ResetPasswordAsync(AppUser user, string token, string newPassword);
  }
}
