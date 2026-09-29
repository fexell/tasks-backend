
using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface IJwtService
  {
    JwtTokenResult GenerateToken(AppUser user, Guid sessionId);
    string GenerateTwoFactorToken(AppUser user);
    string? ValidateTwoFactorToken(string token);
  }
}
