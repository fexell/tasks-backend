using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class ChangePasswordDto
  {
    [Required]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters long.")]
    public string NewPassword { get; set; } = string.Empty;
  }
}