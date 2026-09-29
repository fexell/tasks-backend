using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class LoginDto
  {
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters long.")]
    [MaxLength(128, ErrorMessage = "Password cannot exceed 128 characters.")]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    public string? DeviceFingerprint { get; set; }
  }
}
