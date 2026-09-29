

namespace Entry.Auth.Models
{
  public class LoginRiskAssessment
  {
    public long Id { get; set; }

    public string? UserId { get; set; }
    public string IpAddress { get; set; } = default!;
    public string? Country { get; set; }
    public string? DeviceFingerprint { get; set; }

    public int RiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; }

    public DateTime Timestamp { get; set; }
  }

  public enum RiskLevel
  {
    Low = 0,
    Medium = 1,
    High = 2
  }
}
