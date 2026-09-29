using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class VerifyEmailDto
  {
    [Required(ErrorMessage = "UserId is required")]
    [RegularExpression("^^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", ErrorMessage = "UserId must be a valid GUID")]
    public string? UserId { get; set; }

    [Required(ErrorMessage = "Token is required")]
    [MinLength(32, ErrorMessage = "Token is too short")]
    [MaxLength(512, ErrorMessage = "Token is too long")]
    public string? Token { get; set; }
  }
}
