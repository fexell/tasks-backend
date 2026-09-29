

namespace Entry.Auth.DTOs
{
  public class TokenRotationResultDto
  {
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public int ExpiresInSeconds { get; set; }
    public string UserId { get; set; } = null!;
  }
}