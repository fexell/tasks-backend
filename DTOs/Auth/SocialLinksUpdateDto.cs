using System.ComponentModel.DataAnnotations;

namespace Entry.Auth.DTOs
{
  public class SocialLinksUpdateDto
  {
    [MaxLength(4)]
    public List<string> Urls { get; set; } = new();
  }
}
