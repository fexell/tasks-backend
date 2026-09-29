

using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class ResendVerificationDto
  {
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    [MaxLength(256)]
    [DataType(DataType.EmailAddress)]
    public string? Email { get; set; }
  }
}
