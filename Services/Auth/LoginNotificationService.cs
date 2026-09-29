

using Entry.Auth.Models;
using Entry.Auth.Utils;

namespace Entry.Auth.Services
{
  public class LoginNotificationService : ILoginNotificationService
  {
    private readonly IEmailService _emailService;

    public LoginNotificationService(IEmailService emailService)
    {
      _emailService = emailService;
    }

    public async Task SendLoginNotificationAsync(
      AppUser user,
      string ip,
      string? country,
      string? deviceFingerprint,
      string riskLevel
    )
    {
      var subject = "New login detected!";
      var body = $"""
      <p>A new login has been detected on your account.</p>
      <p>IP: {ip}</p>
      <p>Country: {country ?? "Unknown"}</p>
      <p>Device Fingerprint: {deviceFingerprint ?? "Unknown"}</p>
      <p>Risk Level: {riskLevel}</p>
      <br /><br />
      """;

      await _emailService.SendAsync(user.Email!, subject, body);
    }
  }
}