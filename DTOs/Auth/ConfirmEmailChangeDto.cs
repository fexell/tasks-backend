using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class ConfirmEmailChangeDto
  {
    [Required]
    public string UserId { get; set; } = null!;

    [Required]
    [EmailAddress]
    public string NewEmail { get; set; } = null!;

    [Required]
    public string Token { get; set; } = null!;
  }
}