

namespace Entry.Auth.Models
{
  public class RefreshToken
  {
    public int Id { get; set; }

    public string Token { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public Guid SessionId { get; set; }

    public DateTime ExpiresAt { get; set; }

    public bool Revoked { get; set; } = false;

    // When this token was revoked (usually via rotation). Needed to tell a
    // legitimate concurrent-request race apart from real token theft: reuse
    // seconds after rotation is probably a race, reuse hours later isn't.
    public DateTime? RevokedAt { get; set; }

    // If this token was rotated into a new one, the new token's Id. Lets a
    // reuse-within-grace-period be resolved by just handing back the
    // still-valid successor instead of nuking every session for the user.
    public int? ReplacedByTokenId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public AppUser User { get; set; } = null!;

    public UserSession Session { get; set; } = null!;
  }
}