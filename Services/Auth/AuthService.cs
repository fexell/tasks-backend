using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using Entry.Auth.Data;
using Entry.Auth.Models;
using Entry.Auth.DTOs;

namespace Entry.Auth.Services
{
  public class AuthService : IAuthService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly IJwtService _jwtService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IUserService _userService;
    private readonly IVerificationEmailService _verificationEmailService;
    private readonly ITwoFactorService _twoFactorService;
    private readonly AppDbContext _db;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
      UserManager<AppUser> userManager,
      SignInManager<AppUser> signInManager,
      IJwtService jwtService,
      IRefreshTokenService refreshTokenService,
      IUserService userService,
      IVerificationEmailService verificationEmailService,
      ITwoFactorService twoFactorService,
      AppDbContext db,
      ILogger<AuthService> logger
    )
    {
      _userManager = userManager;
      _signInManager = signInManager;
      _jwtService = jwtService;
      _refreshTokenService = refreshTokenService;
      _userService = userService;
      _verificationEmailService = verificationEmailService;
      _twoFactorService = twoFactorService;
      _db = db;
      _logger = logger;
    }

    // ------------------------------------------------------
    // HELPERS
    // ------------------------------------------------------

    // `error` is the generic, public-facing message (what the client sees in
    // Errors). `reason` is the detailed internal reason used for security
    // logging only - it is never serialized back to the client.
    private static AuthResultDto Fail(string error, AuthFailureReason reason = AuthFailureReason.Other)
    {
      return new AuthResultDto
      {
        Success = false,
        Errors = new List<string> { error },
        FailureReason = reason
      };
    }

    // ------------------------------------------------------
    // REGISTER
    // ------------------------------------------------------

    public async Task<AuthResultDto> RegisterAsync(RegisterDto dto)
    {
      var user = new AppUser
      {
        Email = dto.Email,
        UserName = dto.Username,
        CreatedAt = DateTime.UtcNow
      };

      var createResult = await _userManager.CreateAsync(user, dto.Password!);

      if (!createResult.Succeeded)
      {
        return new AuthResultDto
        {
          Success = false,
          Errors = createResult.Errors.Select(e => e.Description).ToList()
        };
      }

      await _verificationEmailService.SendVerificationEmailAsync(user);

      return new AuthResultDto { Success = true };
    }

    // ------------------------------------------------------
    // LOGIN
    // ------------------------------------------------------

    public async Task<AuthResultDto> LoginAsync(LoginDto dto)
    {
      var normalizedEmail = _userManager.NormalizeEmail(dto.Email);

      var user = await _userManager.Users
        .FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);

      if (user == null)
      {
        // Simulate a password hash to avoid timing attacks
        _userManager.PasswordHasher.HashPassword(null!, "dummy");

        _logger.LogWarning("Login attempt failed: unknown email.");
        return Fail("Invalid credentials.", AuthFailureReason.UnknownEmail);
      }

      var signInResult = await _signInManager.CheckPasswordSignInAsync(user, dto.Password!, lockoutOnFailure: true);

      if (signInResult.IsLockedOut)
      {
        _logger.LogWarning("Login attempt failed: account locked out. UserId: {UserId}", user.Id);
        return Fail("Account is locked. Please try again later.", AuthFailureReason.AccountLocked);
      }

      if (signInResult.IsNotAllowed)
      {
        if (!user.EmailConfirmed)
        {
          _logger.LogWarning("Login attempt failed: email not confirmed. UserId: {UserId}", user.Id);
          return Fail("Please verify your email before logging in.", AuthFailureReason.AccountDisabled);
        }

        _logger.LogWarning("Login attempt failed: not allowed. UserId: {UserId}", user.Id);
        return Fail("Login not allowed.", AuthFailureReason.AccountDisabled);
      }

      if (!signInResult.Succeeded)
      {
        _logger.LogWarning("Login attempt failed: invalid credentials. UserId: {UserId}", user.Id);
        return Fail("Invalid credentials.", AuthFailureReason.InvalidCredentials);
      }

      if (await _userManager.GetTwoFactorEnabledAsync(user))
      {
        var twoFactorToken = _jwtService.GenerateTwoFactorToken(user);

        return new AuthResultDto
        {
          Success = true,
          RequiresTwoFactor = true,
          TwoFactorToken = twoFactorToken
        };
      }

      return await GenerateAuthResultAsync(user);
    }

    // ------------------------------------------------------
    // REFRESH
    // ------------------------------------------------------

    public async Task<AuthResultDto> RefreshAsync(string refreshToken)
    {
      TokenRotationResultDto? result;

      try
      {
        result = await _refreshTokenService.RotateRefreshTokenAsync(refreshToken, expectedUserId: null);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Unexpected error during refresh token rotation.");
        return Fail("Something went wrong. Please try logging in again.");
      }

      if (result == null)
      {
        _logger.LogWarning("Invalid or expired refresh token.");
        return Fail("Invalid or expired refresh token.", AuthFailureReason.InvalidRefreshToken);
      }

      var user = await _userManager.FindByIdAsync(result.UserId);
      if (user == null)
      {
        _logger.LogError("User not found after valid refresh token rotation. UserId: {UserId}", result.UserId);
        return Fail("User not found.");
      }

      var userMe = await _userService.GetUserMeAsync(user);

      return new AuthResultDto
      {
        Success = true,
        AccessToken = result.AccessToken,
        RefreshToken = result.RefreshToken,
        ExpiresIn = result.ExpiresInSeconds,
        User = userMe
      };
    }

    // ------------------------------------------------------
    // SILENT REFRESH
    // ------------------------------------------------------

    public async Task<AuthResultDto> SilentRefreshAsync(AppUser user, string refreshToken)
    {
      TokenPair? pair;

      try
      {
        pair = await _refreshTokenService.RefreshTokenAsync(refreshToken);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Unexpected error during silent refresh. UserId: {UserId}", user.Id);
        return Fail("Something went wrong. Please try logging in again.");
      }

      if (pair == null)
      {
        _logger.LogWarning("Invalid or expired refresh token during silent refresh. UserId: {UserId}", user.Id);
        return Fail("Invalid or expired refresh token.", AuthFailureReason.InvalidRefreshToken);
      }

      var userMe = await _userService.GetUserMeAsync(user);

      return new AuthResultDto
      {
        Success = true,
        AccessToken = pair.AccessToken,
        RefreshToken = pair.RefreshToken,
        ExpiresIn = pair.ExpiresInSeconds,
        User = userMe
      };
    }

    // ------------------------------------------------------
    // REVOKE
    // ------------------------------------------------------

    public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
    {
      return await _refreshTokenService.RevokeRefreshTokenAsync(refreshToken);
    }

    public async Task<bool> RevokeAllUserTokensAsync(string userId)
    {
      return await _refreshTokenService.RevokeAllUserTokensAsync(userId);
    }

    // ------------------------------------------------------
    // EMAIL VERIFICATION
    // ------------------------------------------------------

    public async Task<bool> SendVerificationEmailAsync(AppUser user)
    {
      return await _verificationEmailService.SendVerificationEmailAsync(user);
    }

    public async Task<bool> VerifyEmailAsync(AppUser user, string token)
    {
      return await _userService.VerifyEmailAsync(user, token);
    }

    // ------------------------------------------------------
    // TWO-FACTOR LOGIN
    // ------------------------------------------------------

    public async Task<AuthResultDto> VerifyTwoFactorLoginAsync(VerifyTwoFactorLoginDto dto)
    {
      var userId = _jwtService.ValidateTwoFactorToken(dto.TwoFactorToken);

      if (userId is null)
      {
        return Fail("Your session has expired.");
      }

      var user = await _userManager.FindByIdAsync(userId);

      if (user == null)
      {
        return Fail("Your session has expired. Please log in again.");
      }

      var verified = dto.IsRecoveryCode
        ? await _twoFactorService.VerifyRecoveryCodeAsync(user, dto.Code)
        : await _twoFactorService.VerifyCodeAsync(user, dto.Code);

      if (!verified)
      {
        _logger.LogWarning("Two-factor verification failed. UserId: {UserId}", user.Id);
        return Fail("Invalid verification code.", AuthFailureReason.InvalidTwoFactorCode);
      }

      return await GenerateAuthResultAsync(user);
    }

    // ------------------------------------------------------
    // GENERATE AUTH RESULT
    // ------------------------------------------------------

    private async Task<AuthResultDto> GenerateAuthResultAsync(AppUser user)
    {
      var created = await _refreshTokenService.CreateRefreshTokenAsync(user.Id);
      var jwt = _jwtService.GenerateToken(user, created.SessionId);
      var userMe = await _userService.GetUserMeAsync(user);

      return new AuthResultDto
      {
        Success = true,
        AccessToken = jwt.Token,
        RefreshToken = created.Token,
        ExpiresIn = jwt.ExpiresInSeconds,
        User = userMe
      };
    }
  }
}
