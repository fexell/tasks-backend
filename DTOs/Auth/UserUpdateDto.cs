using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class UserUpdateDto
  {
    [EmailAddress(ErrorMessage = "Invalid email address")]
    [MaxLength(256)]
    public string? Email { get; set; }

    [MinLength(3, ErrorMessage = "Username must be at least 3 characters long")]
    [MaxLength(32, ErrorMessage = "Username must be at most 32 characters long")]
    [RegularExpression("^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string? Username { get; set; }

    [MaxLength(64)]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "First name can only contain letters")]
    public string? FirstName { get; set; }

    [MaxLength(64)]
    [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Last name can only contain letters")]
    public string? LastName { get; set; }

    [MaxLength(256)]
    public string? Avatar { get; set; }

    [MaxLength(160, ErrorMessage = "Bio must be at most 160 characters long")]
    public string? Bio { get; set; }

    [MaxLength(256, ErrorMessage = "Website URL must be at most 256 characters long")]
    public string? WebsiteUrl { get; set; }
  }
}
