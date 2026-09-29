

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface ILoginNotificationService
  {
    Task SendLoginNotificationAsync(AppUser user, string ip, string? country, string? deviceFingerprint, string riskLevel);
  }
}