

namespace Entry.Auth.DTOs
{
  public class ForgotPasswordDto
  {
    public string? Email { get; set; }
  }

  public class ResetPasswordDto
  {
    public string? UserId { get; set; }
    public string? Token { get; set; }
    public string? NewPassword { get; set; }
  }
}