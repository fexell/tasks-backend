using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;

using Entry.Auth.DTOs;
using Entry.Auth.Models;
using Entry.Auth.Services;
using Entry.Auth.Utils;
using System.Security.Claims;

namespace Entry.Auth.Controllers
{
  // ------------------------------------------------------
  // AUTH CONTROLLER
  // ------------------------------------------------------
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController : ControllerBase
  {
    // Duplicated across Login/VerifyTwoFactorLogin/Refresh before - single
    // source now. Consider moving to CookieHelper or config if other
    // controllers ever need the same lifetimes.
    private static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);

    private readonly IAuthService _authService;
    private readonly IUserService _userService;
    private readonly IVerificationEmailService _verificationEmailService;
    private readonly IPasswordResetService _passwordResetService;
    private readonly IBruteForceService _bruteForceService;
    private readonly ITwoFactorService _twoFactorService;
    private readonly IJwtService _jwtService;
    private readonly IAntiforgery _antiforgery;
    private readonly ILoginRiskService _loginRiskService;
    private readonly ILoginNotificationService _loginNotificationService;

    public AuthController(
      IAuthService authService,
      IUserService userService,
      IVerificationEmailService verificationEmailService,
      IPasswordResetService passwordResetService,
      IBruteForceService bruteForceService,
      ITwoFactorService twoFactorService,
      IJwtService jwtService,
      IAntiforgery antiforgery,
      ILoginRiskService loginRiskService,
      ILoginNotificationService loginNotificationService
    )
    {
      _authService = authService;
      _userService = userService;
      _verificationEmailService = verificationEmailService;
      _passwordResetService = passwordResetService;
      _bruteForceService = bruteForceService;
      _twoFactorService = twoFactorService;
      _jwtService = jwtService;
      _antiforgery = antiforgery;
      _loginRiskService = loginRiskService;
      _loginNotificationService = loginNotificationService;
    }

    // ------------------------------------------------------
    // MOBILE CLIENTS
    // ------------------------------------------------------
    // Native apps (the React Native frontend) can't rely on the browser cookie
    // flow: Secure cookies are never sent back over plain http to a LAN IP in
    // development, and HttpOnly protects nothing outside a browser. Mobile
    // clients therefore opt in with "X-Client-Type: mobile" and get the tokens
    // in the response body instead. They store them in the OS keychain/keystore
    // (expo-secure-store) and send them as "Authorization: Bearer <token>".
    // The web frontend never sends this header, so its cookie flow is unchanged.
    private const string ClientTypeHeader = "X-Client-Type";

    private bool IsMobileClient() =>
      string.Equals(Request.Headers[ClientTypeHeader].ToString(), "mobile", StringComparison.OrdinalIgnoreCase);

    private static object MobileTokenResponse(AuthResultDto result, string? message = null) => new
    {
      success = true,
      user = result.User,
      message,
      accessToken = result.AccessToken,
      refreshToken = result.RefreshToken,
      expiresIn = (int)AccessTokenLifetime.TotalSeconds
    };

    // Mobile clients send the refresh token as JSON: { "refreshToken": "..." }
    private async Task<string?> ReadRefreshTokenFromBodyAsync()
    {
      if (!Request.HasJsonContentType()) return null;

      try
      {
        var body = await Request.ReadFromJsonAsync<MobileRefreshTokenDto>();
        return body?.RefreshToken;
      }
      catch (System.Text.Json.JsonException)
      {
        return null;
      }
    }

    // ------------------------------------------------------
    // CSRF TOKEN
    // ------------------------------------------------------

    [AllowAnonymous]
    [HttpGet("csrf-token")]
    public IActionResult GetCsrfToken()
    {
      var tokens = _antiforgery.GetAndStoreTokens(HttpContext);

      return Ok(new { csrfToken = tokens.RequestToken });
    }

    // ------------------------------------------------------
    // REGISTER (NO REDIRECT TO LOGIN)
    // ------------------------------------------------------

    [AllowAnonymous]
    [EnableRateLimiting("AuthPolicy")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
      var result = await _authService.RegisterAsync(dto);

      if (!result.Success) return BadRequest(new { message = "Registration failed.", errors = result.Errors });

      return Ok(new { message = "User created. Please verify your email." });
    }

    // ------------------------------------------------------
    // VERIFY EMAIL
    // ------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto dto)
    {
      var user = await _userService.GetByIdAsync(dto.UserId!);
      if (user == null)
        return NotFound(new { message = "User not found." });

      var success = await _authService.VerifyEmailAsync(user, dto.Token!);

      if (!success)
        return Conflict(new { message = "Email verification failed." });

      return Ok(new { message = "Email verified successfully." });
    }

    // ------------------------------------------------------
    // RESEND VERIFICATION
    // ------------------------------------------------------

    [AllowAnonymous]
    [EnableRateLimiting("AuthPolicy")]
    [HttpPost("resend-verification")]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationDto dto)
    {
      var user = await _userService.GetByEmailAsync(dto.Email!);

      if (user is not null)
        await _verificationEmailService.TryResendVerificationEmailAsync(user);

      return Ok(new { message = "If an account with that email exists and isn't verified yet, a new verification email has been sent." });
    }

    // ------------------------------------------------------
    // LOGIN
    // ------------------------------------------------------

    [AllowAnonymous]
    [EnableRateLimiting("AuthPolicy")]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
      var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
      var userAgent = Request.Headers.UserAgent.ToString();

      // -----------------------------
      // 1. BRUTE-FORCE CHECKS
      // -----------------------------

      if (await _bruteForceService.IsIpBlockedAsync(ip))
      {
        return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many requests from this IP. Please try again later." });
      }

      if (!string.IsNullOrWhiteSpace(dto.Email) && await _bruteForceService.IsEmailBlockedAsync(dto.Email))
      {
        return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many requests from this email. Please try again later." });
      }

      var user = await _userService.GetByEmailAsync(dto.Email!);
      if (user != null && await _bruteForceService.IsUserBlockedAsync(user.Id))
      {
        return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many requests from this user. Please try again later." });
      }

      // -----------------------------
      // 2. RUN LOGIN LOGIC
      // -----------------------------
      var result = await _authService.LoginAsync(dto);

      // Log every attempt right away, regardless of what happens next,
      // so brute-force counters always see it. FailureReason/UserAgent are
      // for internal security logging only - they never reach the client.
      await _bruteForceService.LogAsync(
        endpoint: "login",
        ip: ip,
        email: dto.Email,
        userId: user?.Id,
        success: result.Success,
        failureReason: result.FailureReason,
        userAgent: userAgent
      );

      // -----------------------------
      // 3. FAILED LOGIN -> RETURN EARLY
      // -----------------------------
      // Bail out on bad credentials/locked account before doing anything
      // risk- or 2FA-related. This also avoids burning an ipinfo.io call
      // on every failed attempt.
      if (!result.Success)
      {
        return Unauthorized(new
        {
          message = "Invalid credentials.",
          errors = result.Errors
        });
      }

      // -----------------------------
      // 4. RISK ASSESSMENT (only for valid credentials)
      // -----------------------------

      var deviceFingerprint = dto.DeviceFingerprint;
      var (risk, riskError) = await _loginRiskService.EvaluateAsync(user, ip, deviceFingerprint);

      if(riskError != null)
      {
        return Ok(new
        {
          success = true,
          user= result.User,
          message = "Login successful, but risk assessment failed.",
          code = riskError.Code,
        });
      }

      var requiresTwoFactor = result.RequiresTwoFactor
        || risk!.RiskLevel == RiskLevel.High
        || (risk.RiskLevel == RiskLevel.Medium && user!.TwoFactorEnabled);

      // -----------------------------
      // 5. 2FA REQUIRED -> RETURN
      // -----------------------------
      if (requiresTwoFactor)
      {
        return Ok(new
        {
          requiresTwoFactor = true,
          reason = risk!.RiskLevel == RiskLevel.High ? "suspicious_login"
            : risk.RiskLevel == RiskLevel.Medium ? "medium_risk"
            : (string?)null,
          twoFactorToken = result.TwoFactorToken
        });
      }

      // -----------------------------
      // 6. SET COOKIES (web only - mobile gets the tokens in the body, see step 8)
      // -----------------------------
      if (!IsMobileClient())
      {
        CookieHelper.Set(Response, "accessToken", result.AccessToken!, AccessTokenLifetime);
        CookieHelper.Set(Response, "refreshToken", result.RefreshToken!, RefreshTokenLifetime);
      }

      // -----------------------------
      // 7. UPDATE USER
      // -----------------------------

      user!.LastKnownIp = ip;
      user.LastKnownCountry = risk!.Country;
      user.LastKnownDeviceFingerprint = deviceFingerprint;

      await _userService.UpdateAsync(user);

      // -----------------------------
      // 7.1. LOGIN NOTIFICATION
      // -----------------------------
      // await _loginNotificationService.SendLoginNotificationAsync(user, ip, risk.Country, deviceFingerprint, risk.RiskLevel);

      // -----------------------------
      // 8. RETURN USER AND MESSAGE
      // -----------------------------
      if (IsMobileClient())
        return Ok(MobileTokenResponse(result, "Login successful."));

      return Ok(new
      {
        success = true,
        user = result.User,
        message = "Login successful."
      });
    }

    [AllowAnonymous]
    [EnableRateLimiting("AuthPolicy")]
    [HttpPost("2fa/verify-login")]
    public async Task<IActionResult> VerifyTwoFactorLogin([FromBody] VerifyTwoFactorLoginDto dto)
    {
      var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
      var userAgent = Request.Headers.UserAgent.ToString();

      // -----------------------------
      // 1. BRUTE-FORCE CHECKS
      // -----------------------------
      // Check the cheap IP block before doing any token validation work,
      // same ordering principle as Login below.

      if (await _bruteForceService.IsIpBlockedAsync(ip))
        return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many requests from this IP. Please try again later." });

      var userId = _jwtService.ValidateTwoFactorToken(dto.TwoFactorToken!);

      if (userId == null)
        return Unauthorized(new { message = "Invalid or expired 2FA token." });

      if (await _bruteForceService.IsUserBlockedAsync(userId))
        return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Too many 2FA attempts from this user. Please try again later." });

      // -----------------------------
      // 2. RUN 2FA-VERIFICATION
      // -----------------------------
      var result = await _authService.VerifyTwoFactorLoginAsync(dto);

      // -----------------------------
      // 3. LOG BRUTE FORCE ATTEMPTS
      // -----------------------------

      await _bruteForceService.LogAsync(
        endpoint: "2fa/verify-login",
        ip: ip,
        email: null,
        userId: userId,
        success: result.Success,
        failureReason: result.FailureReason,
        userAgent: userAgent
      );

      // -----------------------------
      // 4. FAILED 2FA
      // -----------------------------

      if (!result.Success)
        return Unauthorized(new { message = "Verification failed.", errors = result.Errors });

      // -----------------------------
      // 5. RISK ASSESSMENT + UPDATE USER
      // -----------------------------
      // Login only updates LastKnownIp/Country/DeviceFingerprint on the
      // direct (non-2FA) path - without this, any user who goes through
      // 2FA never gets those fields refreshed, so LoginRiskService keeps
      // comparing future logins against permanently stale data.

      var user = await _userService.GetByIdAsync(userId);

      if (user is not null)
      {
        var (risk, riskError) = await _loginRiskService.EvaluateAsync(user, ip, dto.DeviceFingerprint);

        user.LastKnownIp = ip;
        user.LastKnownCountry = risk!.Country;
        user.LastKnownDeviceFingerprint = dto.DeviceFingerprint;

        await _userService.UpdateAsync(user);
      }

      // -----------------------------
      // 6. SET COOKIES (web) / RETURN TOKENS IN BODY (mobile)
      // -----------------------------

      if (IsMobileClient())
        return Ok(MobileTokenResponse(result, "Login successful."));

      CookieHelper.Set(Response, "accessToken", result.AccessToken!, AccessTokenLifetime);
      CookieHelper.Set(Response, "refreshToken", result.RefreshToken!, RefreshTokenLifetime);

      // -----------------------------
      // 7. RETURN USER AND MESSAGE
      // -----------------------------

      return Ok(new
      {
        success = result.Success,
        user = result.User,
        message = "Login successful."
      });
    }

    // ------------------------------------------------------
    // REFRESH TOKEN
    // ------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
      var refreshToken = Request.Cookies["refreshToken"];

      // Mobile clients send the refresh token in the body. Tokens are only ever
      // returned in the body when they also *arrived* in the body, so a script
      // running in the browser can never trade the HttpOnly cookie for a
      // readable token by adding the mobile header.
      var fromBody = false;
      if (string.IsNullOrEmpty(refreshToken) && IsMobileClient())
      {
        refreshToken = await ReadRefreshTokenFromBodyAsync();
        fromBody = true;
      }

      if (string.IsNullOrEmpty(refreshToken))
        return Unauthorized(new { message = "No refresh token provided.", errors = new[] { "Missing refresh token." } });

      var result = await _authService.RefreshAsync(refreshToken);

      if (!result.Success)
        return BadRequest(new { message = "Invalid refresh token.", errors = result.Errors });

      if (fromBody)
        return Ok(MobileTokenResponse(result));

      CookieHelper.Set(Response, "accessToken", result.AccessToken!, AccessTokenLifetime);
      CookieHelper.Set(Response, "refreshToken", result.RefreshToken!, RefreshTokenLifetime);

      return Ok(new { user = result.User });
    }

    // ------------------------------------------------------
    // FORGOT PASSWORD
    // ------------------------------------------------------

    [AllowAnonymous]
    [EnableRateLimiting("AuthPolicy")]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
    {
      var user = await _userService.GetByEmailAsync(dto.Email!);

      if (user is not null && user.EmailConfirmed) await _passwordResetService.SendPasswordResetEmailAsync(user);

      return Ok(new { message = "If an account with that email exists and is verified, a password reset email has been sent." });
    }

    // ------------------------------------------------------
    // RESET PASSWORD
    // ------------------------------------------------------

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
    {
      var user = await _userService.GetByIdAsync(dto.UserId!);

      if (user == null) return BadRequest(new { message = "Invalid or expired reset link." });

      var result = await _passwordResetService.ResetPasswordAsync(user, dto.Token!, dto.NewPassword!);

      if (!result.Succeeded)
        return BadRequest(new
        {
          message = "Invalid or expired reset link.",
          errors = result.Errors.Select(e => e.Description)
        });

      await _authService.RevokeAllUserTokensAsync(user.Id);

      return Ok(new { message = "Password reset successfully." });
    }

    // ------------------------------------------------------
    // LOGOUT
    // ------------------------------------------------------

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
      var refreshToken = Request.Cookies["refreshToken"];

      // Mobile clients send their refresh token in the body so it can be revoked.
      if (string.IsNullOrEmpty(refreshToken) && IsMobileClient())
        refreshToken = await ReadRefreshTokenFromBodyAsync();

      if (!string.IsNullOrEmpty(refreshToken))
      {
        await _authService.RevokeRefreshTokenAsync(refreshToken);
      }

      CookieHelper.Delete(Response, "accessToken");
      CookieHelper.Delete(Response, "refreshToken");

      return Ok(new { message = "Logged out." });
    }
  }
}
