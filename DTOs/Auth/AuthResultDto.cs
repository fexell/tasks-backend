using System.Text.Json.Serialization;

using Entry.Auth.Models;

namespace Entry.Auth.DTOs
{
  public class AuthResultDto
  {
    public bool Success { get; set; }
    public List<string>? Errors { get; set; }

    [JsonIgnore]
    public string? AccessToken { get; set; }

    [JsonIgnore]
    public string? RefreshToken { get; set; }

    public int ExpiresIn { get; set; }

    public UserMeDto? User { get; set; }

    public bool RequiresTwoFactor { get; set; }

    public string? TwoFactorToken { get; set; }

    [JsonIgnore]
    public AuthFailureReason FailureReason { get; set; } = AuthFailureReason.None;
  }
}
