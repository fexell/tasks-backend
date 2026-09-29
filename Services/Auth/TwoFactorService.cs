using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Text;

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class TwoFactorService : ITwoFactorService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly ILogger<TwoFactorService> _logger;
    private const string Issuer = "Entry";

    public TwoFactorService(UserManager<AppUser> userManager, ILogger<TwoFactorService> logger)
    {
      _userManager = userManager;
      _logger = logger;
    }

    public async Task<TwoFactorSetupResult> GetSetupInfoAsync(AppUser user)
    {
      var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);

      if (string.IsNullOrEmpty(unformattedKey))
      {
        await _userManager.ResetAuthenticatorKeyAsync(user);
        unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
      }

      var email = await _userManager.GetEmailAsync(user);
      var uri = GenerateQrCodeUri(email!, unformattedKey!);

      return new TwoFactorSetupResult(FormatKey(unformattedKey!), uri);
    }

    public async Task<bool> VerifyAndEnableAsync(AppUser user, string code)
    {
      var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        _userManager.Options.Tokens.AuthenticatorTokenProvider,
        code
      );

      if (!isValid)
      {
        _logger.LogWarning("2FA enable failed: invalid code. UserId: {UserId}", user.Id);
        return false;
      }

      await _userManager.SetTwoFactorEnabledAsync(user, true);

      _logger.LogInformation("2FA enabled. UserId: {UserId}", user.Id);

      return true;
    }

    public async Task<IEnumerable<string>> GenerateRecoveryCodesAsync(AppUser user)
    {
      var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

      _logger.LogInformation("Recovery codes regenerated. UserId: {UserId}", user.Id);

      return codes ?? Enumerable.Empty<string>();
    }

    private static string GenerateQrCodeUri(string email, string unformattedKey)
    {
      return string.Format(
        "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
        Uri.EscapeDataString(Issuer),
        Uri.EscapeDataString(email),
        unformattedKey
      );
    }

    public async Task<bool> VerifyCodeAsync(AppUser user, string code)
    {
      var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        _userManager.Options.Tokens.AuthenticatorTokenProvider,
        code
      );

      if (!isValid)
      {
        _logger.LogWarning("2FA verification failed: invalid code. UserId: {UserId}", user.Id);
      }

      return isValid;
    }

    public async Task<bool> VerifyRecoveryCodeAsync(AppUser user, string recoveryCode)
    {
      var result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, recoveryCode);

      if (!result.Succeeded)
      {
        _logger.LogWarning("2FA recovery code redemption failed. UserId: {UserId}", user.Id);
      }
      else
      {
        _logger.LogInformation("2FA recovery code redeemed. UserId: {UserId}", user.Id);
      }

      return result.Succeeded;
    }

    public async Task<bool> DisableAsync(AppUser user, string code)
    {
      var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        _userManager.Options.Tokens.AuthenticatorTokenProvider,
        code
      );

      if (!isValid)
      {
        _logger.LogWarning("2FA disable failed: invalid code. UserId: {UserId}", user.Id);
        return false;
      }

      await _userManager.SetTwoFactorEnabledAsync(user, false);
      await _userManager.ResetAuthenticatorKeyAsync(user);

      _logger.LogInformation("2FA disabled. UserId: {UserId}", user.Id);

      return true;
    }

    private static string FormatKey(string unformattedKey)
    {
      var result = new StringBuilder();
      int currentPosition = 0;

      while (currentPosition + 4 < unformattedKey.Length)
      {
        result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
        currentPosition += 4;
      }

      if (currentPosition < unformattedKey.Length)
      {
        result.Append(unformattedKey.AsSpan(currentPosition));
      }

      return result.ToString().ToLowerInvariant();
    }
  }
}
