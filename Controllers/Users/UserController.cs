using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Entry.Auth.DTOs;
using Entry.Auth.Models;
using Entry.Auth.Services;
using Entry.Auth.Extensions;

namespace Entry.Auth.Controllers
{
  [Authorize]
  [ApiController]
  [Route("api/[controller]")]
  public class UserController : ControllerBase
  {
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
      _userService = userService;
    }

    // ------------------------------------------------------
    // GET /api/user/{username}
    // ------------------------------------------------------

    [AllowAnonymous]
    [HttpGet("{username}")]
    public async Task<IActionResult> GetByUsername(string username)
    {
      var user = await _userService.GetByUsernameAsync(username);

      if (user == null)
        return NotFound(new { message = "User not found." });

      var dto = await _userService.GetPublicUserAsync(user);

      return Ok(dto);
    }

    // ------------------------------------------------------
    // GET /api/user/me
    // ------------------------------------------------------

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
      string userId;

      try
      {
        userId = User.GetUserId();
      }
      catch
      {
        return Unauthorized();
      }

      var user = await _userService.GetByIdAsync(userId);

      if (user == null)
        return Unauthorized();

      var dto = await _userService.GetUserMeAsync(user);

      return Ok(dto);
    }

    // ------------------------------------------------------
    // PUT /api/user/update
    // ------------------------------------------------------

    [HttpPut("update")]
    public async Task<IActionResult> Update([FromBody] UserUpdateDto dto)
    {
      var userId = User.GetUserId();

      var user = await _userService.GetByIdAsync(userId);
      if (user == null)
        return Unauthorized();

      var success = await _userService.UpdateUserAsync(user, dto);

      if (!success)
        return BadRequest(new { message = "No changes were applied." });

      return Ok(new { message = "User updated successfully." });
    }

    // ------------------------------------------------------
    // DELETE /api/user/delete
    // ------------------------------------------------------

    [HttpDelete("delete")]
    public async Task<IActionResult> Delete([FromBody] DeleteAccountDto dto)
    {
      var userId = User.GetUserId();

      var user = await _userService.GetByIdAsync(userId);

      if(user == null) return Unauthorized();

      var result = await _userService.DeleteUserAsync(user, dto.Password);

      return result switch
      {
        UserDeleteResult.Success => Ok(new { message = "User deleted successfully." }),
        UserDeleteResult.InvalidPassword => BadRequest(new { message = "Invalid password." }),
        _ => BadRequest(new { message = "Failed to delete user." }),
      };
    }
  }
}
