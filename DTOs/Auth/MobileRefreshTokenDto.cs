namespace Entry.Auth.DTOs
{
  // Used by mobile clients, which send their refresh token in the body
  // instead of as a cookie (see AuthController "MOBILE CLIENTS").
  public class MobileRefreshTokenDto
  {
    public string? RefreshToken { get; set; }
  }
}
