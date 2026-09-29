using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class UserMeDto
  {
    [Required]
    public string Id { get; set; } = string.Empty;

    [EmailAddress]
    [MaxLength(256)]
    public string? Email { get; set; }

    [MaxLength(32)]
    [RegularExpression("^[a-zA-Z0-9_]+$")]
    public string? Username { get; set; }

    [MaxLength(160, ErrorMessage = "Bio must be less than 160 characters long.")]
    public string? Bio { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }

    public bool EmailConfirmed { get; set; }

    [MaxLength(256)]
    public string? Avatar { get; set; }

    [MaxLength(64)]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "First name can only contain letters")]
    public string? FirstName { get; set; }

    [MaxLength(64)]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Last name can only contain letters")]
    public string? LastName { get; set; }

    [MaxLength(256, ErrorMessage = "Website URL must be at most 256 characters long")]
    public string? WebsiteUrl { get; set; }

    [MaxLength(4)]
    public List<string> SocialLinks { get; set; } = new();

    public bool Premium { get; set; }
    public bool TwoFactorEnabled { get; set; }
  }
}
