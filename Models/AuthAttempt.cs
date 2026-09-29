using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Entry.Auth.Models
{
  public enum AuthFailureReason
  {
    None = 0,
    InvalidCredentials = 1, // Wrong password for an existing user/account
    UnknownEmail = 2, // No account exists with the given email
    AccountLocked = 3, // Locked out due to prior brute-force detection
    AccountDisabled = 4, // Manually disabled/deleted/unverified
    InvalidTwoFactorCode = 5,
    InvalidRefreshToken = 6,
    Other = 99
  }

  public class AuthAttempt
  {
    [Key]
    public long Id { get; set; }

    [MaxLength(450)]
    public string? UserId { get; set; }

    [MaxLength(256)]
    public string? Email { get; set; }

    [MaxLength(64)]
    public string IpAddress { get; set; } = default!;

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    [MaxLength(64)]
    public string Endpoint { get; set; } = default!;

    public bool Success { get; set; }

    public AuthFailureReason FailureReason { get; set; } = AuthFailureReason.None;

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [ForeignKey(nameof(UserId))]
    public AppUser? User { get; set; }
  }
}