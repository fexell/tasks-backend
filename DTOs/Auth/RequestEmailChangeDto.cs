using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class RequestEmailChangeDto
  {
    [Required]
    [EmailAddress]
    public string NewEmail { get; set; }

    [Required]
    public string Password { get; set; }
  }
}