using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.Models
{
  public class AppUser : IdentityUser
  {
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Optional profile fields (used in UserMeDto)
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Avatar { get; set; }
    public string? Bio { get; set; }
    public bool Premium { get; set; } = false;

    // Navigation property for refresh tokens
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

    // Optional fields for email verification
    public DateTime? LastVerificationEmailSentAt { get; set; }

    public ICollection<UserSession> Sessions { get; set; } = new List<UserSession>();

    [MaxLength(256)]
    public string? WebsiteUrl { get; set; }
    public ICollection<SocialLink> SocialLinks { get; set; } = new List<SocialLink>();

    public string? LastKnownIp { get; set; }
    public string? LastKnownCountry { get; set; }
    public string? LastKnownDeviceFingerprint { get; set; }
  }
}
