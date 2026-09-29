using System;
using System.Collections.Generic;

namespace Entry.Auth.Models
{
  public class UserSession
  {
    public Guid Id { get; set; }
    public string UserId { get; set; } = default!;

    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastUsedAt { get; set; } = DateTime.UtcNow;

    // Must be nullable
    public DateTime? RevokedAt { get; set; }

    // Required navigation property
    public AppUser User { get; set; } = null!;

    // Required for EF relationship
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
  }
}
