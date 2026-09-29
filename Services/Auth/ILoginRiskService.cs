

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public interface ILoginRiskService
  {
    Task<(LoginRiskAssessment? Assessment, ServiceError? Error)> EvaluateAsync(AppUser? user, string ip, string? deviceFingerprint);
    Task<ServiceError?> SendSuspiciousLoginEmailAsync(AppUser user, LoginRiskAssessment assessment);
    Task<(string? CountryCode, ServiceError? Error)> GetCountryCodeFromIpAsync(string ip);
  }
}