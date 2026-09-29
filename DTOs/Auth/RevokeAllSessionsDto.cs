using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class RevokeAllSessionsDto
  {
    [Required]
    public string Password { get; set; } = string.Empty;
  }
}
