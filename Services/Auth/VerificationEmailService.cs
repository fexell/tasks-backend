using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class VerificationEmailService : IVerificationEmailService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly IFrontendUrlProvider _urlProvider;
    private readonly ILogger<VerificationEmailService> _logger;
    private readonly TimeSpan _tokenLifespan;

    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);

    public VerificationEmailService(
      UserManager<AppUser> userManager,
      IEmailService emailService,
      IConfiguration config,
      IWebHostEnvironment env,
      IFrontendUrlProvider urlProvider,
      ILogger<VerificationEmailService> logger,
      IOptions<DataProtectionTokenProviderOptions> tokenOptions
    )
    {
      _userManager = userManager;
      _emailService = emailService;
      _config = config;
      _env = env;
      _urlProvider = urlProvider;
      _logger = logger;
      _tokenLifespan = tokenOptions.Value.TokenLifespan;
    }

    public async Task<bool> SendVerificationEmailAsync(AppUser user)
    {
      var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
      var link = _urlProvider.BuildUrl($"/auth/verify-email?userId={user.Id}&token={Uri.EscapeDataString(token)}");
      var resendLink = _urlProvider.BuildUrl("auth/resend-verification");

      _logger.LogDebug(
        "Generated email verification token for UserId: {UserId}. Link: {Link}",
        user.Id,
        link
      );

      var expiryText = FormatLifespan(_tokenLifespan);

      try
      {
        await _emailService.SendAsync(
          user.Email!,
          "Verify your email",
          $@"<p>Please verify your email by clicking the link below:</p>
             <p><a href='{link}'>Verify Email</a></p>
             <p>This link will expire in {expiryText}.</p>
             <p>If it has expired, you can request a new one here: <a href='{resendLink}'>Resend verification email</a></p>"
        );
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Failed to send verification email to UserId: {UserId}.", user.Id);
        return false;
      }

      user.LastVerificationEmailSentAt = DateTime.UtcNow;
      await _userManager.UpdateAsync(user);

      _logger.LogInformation("Verification email sent to UserId: {UserId}.", user.Id);

      return true;
    }

    public async Task<(bool Sent, TimeSpan? RetryAfter)> TryResendVerificationEmailAsync(AppUser user)
    {
      if (user.EmailConfirmed)
      {
        return (false, null);
      }

      if (user.LastVerificationEmailSentAt is DateTime last)
      {
        var elapsed = DateTime.UtcNow - last;
        if (elapsed < ResendCooldown)
        {
          return (false, ResendCooldown - elapsed);
        }
      }

      var sent = await SendVerificationEmailAsync(user);

      return (sent, null);
    }

    private static string FormatLifespan(TimeSpan span)
    {
      if (span.TotalDays >= 1)
        return span.TotalDays == 1 ? "1 day" : $"{(int)span.TotalDays} days";

      if (span.TotalHours >= 1)
        return span.TotalHours == 1 ? "1 hour" : $"{(int)span.TotalHours} hours";

      return span.TotalMinutes == 1 ? "1 minute" : $"{(int)span.TotalMinutes} minutes";
    }
  }
}
