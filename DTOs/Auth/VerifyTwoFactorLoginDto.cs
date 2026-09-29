

namespace Entry.Auth.DTOs
{
  public class VerifyTwoFactorLoginDto
  {
    public string TwoFactorToken { get; set; } = null!;
    public string Code { get; set; } = null!;
    public bool IsRecoveryCode { get; set; } = false;
    public string? DeviceFingerprint { get; set; }
  }
}
