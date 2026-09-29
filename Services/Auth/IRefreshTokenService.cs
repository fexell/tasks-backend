

using Entry.Auth.Models;
using Entry.Auth.DTOs;

namespace Entry.Auth.Services
{
  public interface IRefreshTokenService
  {
    Task<CreatedRefreshToken> CreateRefreshTokenAsync(string userId, Guid? sessionId = null, string? userAgent = null, string? ipAddress = null);

    Task<TokenPair?> RefreshTokenAsync(string refreshToken);
    Task<bool> RevokeRefreshTokenAsync(string refreshToken);
    Task<bool> RevokeAllUserTokensAsync(string userId);

    Task<IEnumerable<SessionDto>> GetActiveSessionsAsync(string userId, string? currentRefreshToken);
    Task<bool> RevokeSessionAsync(string userId, Guid sessionId);
    Task RevokeAllSessionsExceptCurrentAsync(string userId, string? currentRefreshToken);
    Task<TokenRotationResultDto?> RotateRefreshTokenAsync(string refreshToken, string? expectedUserId);
  }
}