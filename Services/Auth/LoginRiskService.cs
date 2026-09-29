using System.Net;
using System.Web;
using Microsoft.Extensions.Caching.Memory;

using Entry.Auth.Data;
using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class LoginRiskService : ILoginRiskService
  {
    private readonly IUserService _userService;
    private readonly IEmailService _emailService;
    private readonly HttpClient _httpClient;
    private readonly AppDbContext _db;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _config;

    private static readonly TimeSpan HitTtl = TimeSpan.FromHours(12);
    private static readonly TimeSpan MissTtl = TimeSpan.FromMinutes(5);

    // Risk scoring weights — consider moving to appsettings if you want
    // these tunable without a redeploy.
    private const int NewIpScore = 30;
    private const int NewCountryScore = 40;
    private const int NewDeviceScore = 30;
    private const int UnusualTimeScore = 10;
    private const int HighRiskThreshold = 70;
    private const int MediumRiskThreshold = 30;

    public LoginRiskService(
      IUserService userService,
      IEmailService emailService,
      AppDbContext db,
      HttpClient httpClient,
      IMemoryCache cache,
      IConfiguration config
    )
    {
      _userService = userService;
      _emailService = emailService;
      _db = db;
      _httpClient = httpClient;
      _cache = cache;
      _config = config;
    }

    public async Task<(LoginRiskAssessment? Assessment, ServiceError? Error)> EvaluateAsync(
      AppUser? user,
      string ip,
      string? deviceFingerprint
    )
    {
      // NOTE: countryCode is an ISO code (e.g. "SE"), not a display name.
      // Display names are only resolved when rendering the email.
      var (countryCode, geoError) = await GetCountryCodeFromIpAsync(ip);

      int score = 0;

      if (user != null && user.LastKnownIp != null && user.LastKnownIp != ip)
      {
        score += NewIpScore;
      }

      if (user != null && user.LastKnownCountry != null && countryCode != null && user.LastKnownCountry != countryCode)
      {
        score += NewCountryScore;
      }

      if (user != null && user.LastKnownDeviceFingerprint != null && user.LastKnownDeviceFingerprint != deviceFingerprint)
      {
        score += NewDeviceScore;
      }

      var hour = DateTime.UtcNow.Hour;
      if (hour < 5 || hour > 23)
      {
        score += UnusualTimeScore;
      }

      RiskLevel level =
        score >= HighRiskThreshold ? RiskLevel.High :
        score >= MediumRiskThreshold ? RiskLevel.Medium :
        RiskLevel.Low;

      var assessment = new LoginRiskAssessment
      {
        UserId = user?.Id,
        IpAddress = ip,
        Country = countryCode,
        DeviceFingerprint = deviceFingerprint,
        RiskScore = score,
        RiskLevel = level,
        Timestamp = DateTime.UtcNow
      };

      _db.LoginRiskAssessments.Add(assessment);
      await _db.SaveChangesAsync();

      ServiceError? emailError = null;

      if (level == RiskLevel.High && user != null)
      {
        emailError = await SendSuspiciousLoginEmailAsync(user, assessment);
      }

      if(emailError != null)
      {
        return (assessment, emailError);
      }

      if(geoError != null)
      {
        return (assessment, geoError);
      }

      return (assessment, null);
    }

    public async Task<ServiceError?> SendSuspiciousLoginEmailAsync(AppUser user, LoginRiskAssessment assessment)
    {
      var subject = "Security Alert: Suspicious Login Detected";

      var countryDisplay = HttpUtility.HtmlEncode(
        CountryCodeToName(assessment.Country) ?? assessment.Country ?? "Unknown"
      );
      var ipDisplay = HttpUtility.HtmlEncode(assessment.IpAddress);
      var fingerprintDisplay = HttpUtility.HtmlEncode(assessment.DeviceFingerprint ?? "Unknown");
      var riskLevelDisplay = HttpUtility.HtmlEncode(assessment.RiskLevel.ToString());

      var body = $"""
      <p>Hi,</p>
      <p>We have detected a suspicious login attempt on your account.</p>
      <p>Details:</p>
      <ul>
        <li>IP: {ipDisplay}</li>
        <li>Country: {countryDisplay}</li>
        <li>Device Fingerprint: {fingerprintDisplay}</li>
        <li>Risk Level: {riskLevelDisplay}</li>
      </ul>
      <p>If this was not you, please revoke all active sessions immediately:
      {_config["AppUrls:FrontendBaseUrl"]}/settings/sessions
      </p>
      """;

      try
      {
        await _emailService.SendAsync(user.Email!, subject, body);
        return null;
      }
      catch
      {
        return new ServiceError{
          Message = "Failed to send security alert email.",
          Code = "EMAIL_SEND_FAILED"
        };
      }
    }

    public async Task<(string? CountryCode, ServiceError? Error)> GetCountryCodeFromIpAsync(string ip)
    {
      if (IsPrivateOrLoopback(ip))
      {
        return (null, null);
      }

      var cacheKey = $"geoip:{ip}";

      if (_cache.TryGetValue<string?>(cacheKey, out var cached))
      {
        return (cached, null);
      }

      var (result, error) = await FetchCountryCodeFromIpAsync(ip);

      _cache.Set(cacheKey, result, result != null ? HitTtl : MissTtl);

      return (result, error);
    }

    private static bool IsPrivateOrLoopback(string ip)
    {
      if (string.IsNullOrWhiteSpace(ip))
      {
        return true;
      }

      if (!IPAddress.TryParse(ip, out var address))
      {
        return true;
      }

      if (IPAddress.IsLoopback(address))
      {
        return true;
      }

      if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
      {
        var bytes = address.GetAddressBytes();

        return bytes[0] == 10
          || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
          || (bytes[0] == 192 && bytes[1] == 168);
      }

      if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
      {
        var bytes = address.GetAddressBytes();

        // fc00::/7 (unique local) and fe80::/10 (link-local)
        return (bytes[0] & 0xFE) == 0xFC || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
      }

      return false;
    }

    private async Task<(string? CountryCode, ServiceError? Error)> FetchCountryCodeFromIpAsync(string ip)
    {
      try
      {
        var token = _config["IpInfo:Token"];

        if (string.IsNullOrWhiteSpace(token))
        {
          return (null, new ServiceError
          {
            Message = "IP geolocation is not configured.",
            Code = "GEOIP_NOT_CONFIGURED"
          });
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://ipinfo.io/{ip}/country");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await _httpClient.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
          return (null, new ServiceError
          {
            Message = "Failed to resolve country from IP.",
            Code = "GEOIP_LOOKUP_FAILED"
          });
        }

        var content = (await response.Content.ReadAsStringAsync()).Trim();
        var country = string.IsNullOrWhiteSpace(content) ? null : content.ToUpperInvariant();

        return (country, country is null
          ? new ServiceError
          {
            Message = "Failed to resolve country from IP.",
            Code = "GEOIP_LOOKUP_FAILED"
          } : null);
      }
      catch
      {
        // Timeouts, DNS failures, rate limiting, etc. all fall back to
        // "unknown country" rather than blocking or failing the login.
        return (null, new ServiceError
        {
          Message = "Failed to resolve country from IP.",
          Code = "GEOIP_LOOKUP_FAILED"
        });
      }
    }

    private static string? CountryCodeToName(string? code)
    {
      return code switch
      {
        "SE" => "Sweden",
        "NO" => "Norway",
        "DK" => "Denmark",
        "FI" => "Finland",
        "US" => "United States",
        "GB" => "United Kingdom",
        "DE" => "Germany",
        "FR" => "France",
        "NL" => "Netherlands",
        "ES" => "Spain",
        "IT" => "Italy",
        "PL" => "Poland",
        "CA" => "Canada",
        "AU" => "Australia",
        _ => null
      };
    }
  }
}
