

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface ITwoFactorService
  {
    Task<TwoFactorSetupResult> GetSetupInfoAsync(AppUser user);
    Task<bool> VerifyAndEnableAsync(AppUser user, string code);
    Task<IEnumerable<string>> GenerateRecoveryCodesAsync(AppUser user);
    
    Task<bool> VerifyCodeAsync(AppUser user, string code);
    Task<bool> VerifyRecoveryCodeAsync(AppUser user, string recoveryCode);
    Task<bool> DisableAsync(AppUser user, string code);
  }

  public record TwoFactorSetupResult(string SharedKey, string AuthenticatorUri);
}