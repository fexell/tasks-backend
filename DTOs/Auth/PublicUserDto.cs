

namespace Entry.Auth.DTOs
{
  public class PublicUserDto
  {
    public string Id { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Bio { get; set; }
    public string? Avatar { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool Premium { get; set; }
    public string? WebsiteUrl { get; set; }
    public List<string> SocialLinks { get; set; } = new();
  }
}