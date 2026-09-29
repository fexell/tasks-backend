using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Entry.Auth.Services;
using Entry.Auth.Extensions;
using Entry.Auth.DTOs;
using Entry.Auth.Models;

namespace Entry.Auth.Controllers
{
  // ------------------------------------------------------
  // ACCOUNT CONTROLLER
  // ------------------------------------------------------
  [ApiController]
  [Authorize]
  [Route("api/[controller]")]
  public class AccountController : ControllerBase
  {
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IUserService _userService;
    private readonly IEmailChangeService _emailChangeService;

    public AccountController(IRefreshTokenService refreshTokenService, IUserService userService, IEmailChangeService emailChangeService)
    {
      _refreshTokenService = refreshTokenService;
      _userService = userService;
      _emailChangeService = emailChangeService;
    }

    // ------------------------------------------------------
    // HELPERS
    // ------------------------------------------------------

    // GET CURRENT USER'S ID
    private async Task<AppUser?> GetCurrentUserAsync()
    {
      var userId = User.GetUserId();

      if(userId == null) return null;

      return await _userService.GetByIdAsync(userId);
    }

    // GET CURRENT USER OR RETURN 404
    private async Task<(AppUser? user, IActionResult? error)> GetCurrentUserOrNotFoundAsync()
    {
      var user = await GetCurrentUserAsync();
      if(user == null) return (null, NotFound(new { message = "User not found." }));

      return (user, null);
    }

    // REQUIRE VALID PASSWORD
    private async Task<(bool isValid, IActionResult? error)> RequireValidPasswordAsync(AppUser user, string password)
    {
      var valid = await _userService.CheckPasswordAsync(user, password);
      if(!valid) return (false, BadRequest(new { message = "Incorrect password." }));

      return (true, null);
    }

    // GET CURRENT REFRESH TOKEN
    private string? GetCurrentRefreshToken()
    {
      return Request.Cookies["refreshToken"];
    }

    // REQUIRE REFRESH TOKEN
    private (string? token, IActionResult? error) RequireRefreshToken()
    {
      var token = GetCurrentRefreshToken();
      if(string.IsNullOrEmpty(token)) return (null, BadRequest(new { message = "Missing refresh token." }));

      return (token, null);
    }

    // ------------------------------------------------------
    // ENDPOINTS
    // ------------------------------------------------------

    // GET ALL ACTIVE SESSIONS ACROSS ALL DEVICES
    [HttpGet("sessions")]
    public async Task<IActionResult> GetSessions()
    {
      var userId = User.GetUserId();
      var currentRefreshToken = Request.Cookies["refreshToken"];

      var sessions = await _refreshTokenService.GetActiveSessionsAsync(userId, currentRefreshToken);

      return Ok(sessions);
    }

    // REVOKE A SPECIFIC SESSION
    [HttpDelete("sessions/{id}")]
    public async Task <IActionResult> RevokeSession(Guid id, [FromBody] RevokeSessionDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var (valid, passwordError) = await RequireValidPasswordAsync(user!, dto.Password);
      if(passwordError != null) return passwordError;

      var revoked = await _refreshTokenService.RevokeSessionAsync(user!.Id, id);
      if(!revoked) return NotFound(new { message = "Session not found." });

      return Ok(new { message = "Session revoked successfully." });
    }

    // REVOKE ALL SESSIONS EXCEPT CURRENT (REQUIRES VALID PASSWORD AND CURRENT REFRESH TOKEN)
    [HttpPost("sessions/revoke-all")]
    public async Task<IActionResult> RevokeAllSessions([FromBody] RevokeAllSessionsDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var (valid, passwordError) = await RequireValidPasswordAsync(user!, dto.Password);
      if(passwordError != null) return passwordError;

      var (currentRefreshToken, refreshTokenError) = RequireRefreshToken();
      if(refreshTokenError != null) return refreshTokenError;

      await _refreshTokenService.RevokeAllSessionsExceptCurrentAsync(user!.Id, currentRefreshToken);

      return Ok(new { message = "All sessions revoked successfully." });
    }

    // UPDATE PROFILE (FIRST NAME, LAST NAME, ETC.)
    [HttpPatch("profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UserUpdateDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var success = await _userService.UpdateUserAsync(user!, dto);
      if(!success) return BadRequest(new { message = "Could not update profile." });

      var me = await _userService.GetUserMeAsync(user!);
      return Ok(new { message = "Profile updated successfully.", user = me });
    }

    [HttpPut("social-links")]
    public async Task<IActionResult> UpdateSocialLinks([FromBody] SocialLinksUpdateDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var success = await _userService.UpdateSocialLinksAsync(user!, dto);
      if(!success) return BadRequest(new { message = "Could not update social links." });

      var me = await _userService.GetUserMeAsync(user!);
      return Ok(new { message = "Social links updated successfully.", user = me });
    }

    // CHANGE PASSWORD
    [HttpPatch("password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var result = await _userService.ChangePasswordAsync(user!, dto);
      if (!result.Succeeded)
      {
        return BadRequest(new
        {
          message = "Could not change password.",
          errors = result.Errors.Select(e => e.Description).ToList()
        });
      }

      var (currentRefreshToken, refreshTokenError) = RequireRefreshToken();
      if(refreshTokenError != null) return refreshTokenError;

      await _refreshTokenService.RevokeAllSessionsExceptCurrentAsync(user!.Id, currentRefreshToken);

      return Ok(new { message = "Password changed successfully." });
    }

    // REQUEST EMAIL CHANGE
    [HttpPost("email/change-request")]
    public async Task<IActionResult> RequestEmailChange([FromBody] RequestEmailChangeDto dto)
    {
      var (user, error) = await GetCurrentUserOrNotFoundAsync();
      if(error != null) return error;

      var result = await _emailChangeService.RequestEmailChangeAsync(user!, dto.NewEmail, dto.Password);

      return result switch
      {
        EmailChangeResult.Success => Ok(new { message = "A confirmation email has been sent to your new email address." }),
        EmailChangeResult.InvalidPassword => BadRequest(new { message = "Incorrect password." }),
        EmailChangeResult.EmailInUse => BadRequest(new { message = "That email address is already in use." }),
        EmailChangeResult.SameEmail => BadRequest(new { message = "You cannot change to the same email address." }),
        _ => BadRequest(new { message = "Could not process request." }),
      };
    }

    // CONFIRM EMAIL CHANGE
    [AllowAnonymous]
    [HttpPost("email/change-confirm")]
    public async Task<IActionResult> ConfirmEmailChange([FromBody] ConfirmEmailChangeDto dto)
    {
      var user = await _userService.GetByIdAsync(dto.UserId);
      if(user == null) return BadRequest(new { message = "Invalid or expired confirmation link." });

      var success = await _emailChangeService.ConfirmEmailChangeAsync(user, dto.NewEmail, dto.Token);
      if(!success) return BadRequest(new { message = "Invalid or expired confirmation link." });

      await _refreshTokenService.RevokeAllUserTokensAsync(user.Id);

      return Ok(new { message = "Email changed successfully. Please sign in with your new email address." });
    }
  }
}