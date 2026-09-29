

namespace Entry.Auth.DTOs
{
  public class TokenPairDto
  {
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public int ExpiresInSeconds { get; set; }
  }
}