using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class DeleteAccountDto
  {
    [Required(ErrorMessage = "Password is required.")]
    public string Password { get; set; } = string.Empty;
  }
}