using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class RegisterDto
  {
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string? Email { get; set; } = null!;

    [Required]
    [MinLength(3, ErrorMessage = "Username must be at least 3 characters long")]
    [MaxLength(32, ErrorMessage = "Username cannot exceed 32 characters")]
    [RegularExpression("^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string? Username { get; set; } = null!;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters long")]
    [MaxLength(128, ErrorMessage = "Password cannot exceed 128 characters")]
    [DataType(DataType.Password)]
    public string? Password { get; set; } = null!;
  }
}
