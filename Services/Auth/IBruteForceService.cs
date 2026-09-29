

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface IBruteForceService
  {
    Task LogAsync(
      string endpoint,
      string ip,
      string? email,
      string? userId,
      bool success,
      AuthFailureReason failureReason = AuthFailureReason.None,
      string? userAgent = null
    );
    Task<bool> IsIpBlockedAsync(string ip);
    Task<bool> IsEmailBlockedAsync(string email);
    Task<bool> IsUserBlockedAsync(string userId);
  }
}
