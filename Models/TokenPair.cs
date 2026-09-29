

namespace Entry.Auth.Models
{
  public class TokenPair
  {
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
    public required int ExpiresInSeconds { get; set; }
    public string SessionId { get; set; } = null!;
    public string UserId { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
  }
}