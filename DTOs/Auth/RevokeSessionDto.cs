using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class RevokeSessionDto
  {
    [Required]
    public string Password { get; set; } = string.Empty;
  }
}
