using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Web;

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class PasswordResetService : IPasswordResetService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly IEmailService _emailSender;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly ILogger<PasswordResetService> _logger;

    public PasswordResetService(
      UserManager<AppUser> userManager,
      IEmailService emailSender,
      IConfiguration config,
      IWebHostEnvironment env,
      ILogger<PasswordResetService> logger
    )
    {
      _userManager = userManager;
      _emailSender = emailSender;
      _config = config;
      _env = env;
      _logger = logger;
    }

    // ------------------------------------------------------
    // SEND RESET EMAIL
    // ------------------------------------------------------

    public async Task<bool> SendPasswordResetEmailAsync(AppUser user)
    {
      var token = await _userManager.GeneratePasswordResetTokenAsync(user);
      var encodedToken = HttpUtility.UrlEncode(token);

      var frontendUrl = _env.IsDevelopment() ? "http://localhost:3000" : _config["AppUrls:FrontendBaseUrl"];
      var resetLink = $"{frontendUrl}/auth/reset-password?userId={user.Id}&token={encodedToken}";

      var subject = "Reset your password";
      var body = $"""
      <p>We received a request to reset your password.</p>
      <p><a href="{resetLink}">Click here to reset your password</a></p>
      <p>If you did not make this request, you can ignore this email.</p>
      """;

      try
      {
        await _emailSender.SendAsync(user.Email!, subject, body);

        _logger.LogInformation("Password reset email sent to UserId: {UserId}.", user.Id);
        return true;
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Failed to send password reset email to UserId: {UserId}.", user.Id);
        return false;
      }
    }

    // ------------------------------------------------------
    // RESET PASSWORD
    // ------------------------------------------------------

    public async Task<IdentityResult> ResetPasswordAsync(AppUser user, string token, string newPassword)
    {
      var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

      if (!result.Succeeded)
      {
        _logger.LogWarning(
          "Password reset failed for UserId: {UserId}. Errors: {Errors}",
          user.Id,
          string.Join(", ", result.Errors.Select(e => e.Description))
        );

        return result;
      }

      await _userManager.UpdateSecurityStampAsync(user);

      _logger.LogInformation("Password reset succeeded for UserId: {UserId}.", user.Id);

      return result;
    }
  }
}
