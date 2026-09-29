using Entry.Auth.Models;
using Entry.Auth.DTOs;

namespace Entry.Auth.Services
{
  public interface IAuthService
  {
    Task<AuthResultDto> RegisterAsync(RegisterDto dto);
    Task<AuthResultDto> LoginAsync(LoginDto dto);
    Task<AuthResultDto> VerifyTwoFactorLoginAsync(VerifyTwoFactorLoginDto dto);
    Task<AuthResultDto> RefreshAsync(string refreshToken);
    Task<AuthResultDto> SilentRefreshAsync(AppUser user, string refreshToken);

    Task<bool> RevokeRefreshTokenAsync(string refreshToken);
    Task<bool> RevokeAllUserTokensAsync(string userId);

    Task<bool> SendVerificationEmailAsync(AppUser user);
    Task<bool> VerifyEmailAsync(AppUser user, string token);
  }
}
