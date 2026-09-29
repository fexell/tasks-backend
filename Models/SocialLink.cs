

namespace Entry.Auth.Models
{
  public class SocialLink
  {
    public Guid Id { get; set; }
    public string UserId { get; set; } = null!;
    public string Url { get; set; } = null!;
    public int SortOrder { get; set; }

    public AppUser User { get; set; } = null!;
  }
}