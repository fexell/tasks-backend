using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Entry.Auth.Models;
using Entry.Auth.Services;
using Microsoft.AspNetCore.Authorization;

namespace Entry.Auth.Controllers
{
  // ------------------------------------------------------
  // 2FA CONTROLLER
  // ------------------------------------------------------
  [ApiController]
  [Route("api/2fa")]
  [Authorize]
  public class TwoFactorController : ControllerBase
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly ITwoFactorService _twoFactorService;

    public TwoFactorController(UserManager<AppUser> userManager, ITwoFactorService twoFactorService)
    {
      _userManager = userManager;
      _twoFactorService = twoFactorService;
    }

    // ------------------------------------------------------
    // ENDPOINTS
    // ------------------------------------------------------

    // SETUP THE 2FA
    [HttpPost("setup")]
    public async Task<IActionResult> GetSetup()
    {
      var user = await _userManager.GetUserAsync(User);

      if(user is null) return Unauthorized(new { message = "User not found." });

      var result = await _twoFactorService.GetSetupInfoAsync(user);

      return Ok(result);
    }

    // ENABLE THE 2FA
    [HttpPost("enable")]
    public async Task<IActionResult> Enable([FromBody] VerifyTwoFactorSetupRequest request)
    {
      var user = await _userManager.GetUserAsync(User);

      if(user is null) return Unauthorized();

      var success = await _twoFactorService.VerifyAndEnableAsync(user, request.Code);

      if(!success) return BadRequest(new { message = "Invalid verification code" });

      var recoveryCodes = await _twoFactorService.GenerateRecoveryCodesAsync(user);

      return Ok(new { recoveryCodes, success = true, message = "2FA enabled successfully." });
    }

    // DISABLE THE 2FA
    [HttpPost("disable")]
    public async Task<IActionResult> Disable([FromBody] DisableTwoFactorRequest request)
    {
      var user = await _userManager.GetUserAsync(User);

      if(user is null) return Unauthorized();

      var success = await _twoFactorService.DisableAsync(user, request.Code);

      if(!success) return BadRequest(new { message = "Invalid verification code" });

      return Ok(new { success = true, message = "2FA disabled successfully." });
    }

    // REGENERATE RECOVERY CODES
    [HttpPost("recovery-codes/regenerate")]
    public async Task<IActionResult> RegenerateRecoveryCodes([FromBody] RegenerateRecoveryCodesRequest request)
    {
      var user = await _userManager.GetUserAsync(User);

      if(user is null) return Unauthorized();

      var isValid = await _twoFactorService.VerifyCodeAsync(user, request.Code);

      if(!isValid) return BadRequest(new { message = "Invalid verification code" });

      var recoveryCodes = await _twoFactorService.GenerateRecoveryCodesAsync(user);

      return Ok(new { recoveryCodes, success = true, message = "Recovery codes regenerated successfully." });
    }
  }

  public record VerifyTwoFactorSetupRequest(string Code);
  public record DisableTwoFactorRequest(string Code);
  public record RegenerateRecoveryCodesRequest(string Code);
}
