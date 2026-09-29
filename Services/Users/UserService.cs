using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using Entry.Auth.Data;
using Entry.Auth.Models;
using Entry.Auth.DTOs;

namespace Entry.Auth.Services
{
  public class UserService : IUserService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly IVerificationEmailService _verificationEmailService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly AppDbContext _db;

    public UserService(
      UserManager<AppUser> userManager,
      IVerificationEmailService verificationEmailService,
      IRefreshTokenService refreshTokenService,
      AppDbContext db
    )
    {
      _userManager = userManager;
      _verificationEmailService = verificationEmailService;
      _refreshTokenService = refreshTokenService;
      _db = db;
    }

    private static string? NormalizeOptional(string? value)
    {
      return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    // ------------------------------------------------------
    // GET USER
    // ------------------------------------------------------

    public async Task<AppUser?> GetByIdAsync(string userId)
    {
      return await _userManager.Users
        .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<AppUser?> GetByEmailAsync(string email)
    {
      return await _userManager.Users
        .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<AppUser?> GetByUsernameAsync(string username)
    {
      return await _userManager.Users
        .FirstOrDefaultAsync(u => u.UserName == username);
    }

    // ------------------------------------------------------
    // UPDATE USER
    // ------------------------------------------------------

    public async Task<bool> UpdateAsync(AppUser user)
    {
      var result = await _userManager.UpdateAsync(user);

      return result.Succeeded;
    }

    public async Task<bool> UpdateUserAsync(AppUser user, UserUpdateDto dto)
    {
      var updated = false;

      if (!string.IsNullOrWhiteSpace(dto.Username) && dto.Username != user.UserName)
      {
        user.UserName = dto.Username;
        await _userManager.UpdateNormalizedUserNameAsync(user);
        updated = true;
      }

      if(dto.FirstName != null && dto.FirstName != user.FirstName)
      {
        user.FirstName = dto.FirstName;
        updated = true;
      }

      if(dto.LastName != null && dto.LastName != user.LastName)
      {
        user.LastName = dto.LastName;
        updated = true;
      }

      if(dto.Bio != null && dto.Bio != user.Bio)
      {
        user.Bio = NormalizeOptional(dto.Bio);
        updated = true;
      }

      if(dto.WebsiteUrl != null && dto.WebsiteUrl != user.WebsiteUrl)
      {
        user.WebsiteUrl = NormalizeOptional(dto.WebsiteUrl);
        updated = true;
      }

      if (!updated) return true;

      var result = await _userManager.UpdateAsync(user);

      return result.Succeeded;
    }

    // ------------------------------------------------------
    // DELETE USER
    // ------------------------------------------------------

    public async Task<UserDeleteResult> DeleteUserAsync(AppUser user, string password)
    {
      var passwordValid = await _userManager.CheckPasswordAsync(user, password);
      if(!passwordValid) return UserDeleteResult.InvalidPassword;

      var refreshTokens = await _db.RefreshTokens
        .Where(rt => rt.UserId == user.Id)
        .ToListAsync();

      var sessions = await _db.UserSessions
        .Where(s => s.UserId == user.Id)
        .ToListAsync();
      _db.UserSessions.RemoveRange(sessions);

      await _db.SaveChangesAsync();

      var result = await _userManager.DeleteAsync(user);

      return result.Succeeded ? UserDeleteResult.Success : UserDeleteResult.Failed;
    }

    // ------------------------------------------------------
    // EMAIL CONFIRMATION
    // ------------------------------------------------------

    public async Task<bool> IsEmailConfirmedAsync(AppUser user)
    {
      return await _userManager.IsEmailConfirmedAsync(user);
    }

    public async Task<string> GenerateEmailVerificationTokenAsync(AppUser user)
    {
      return await _userManager.GenerateEmailConfirmationTokenAsync(user);
    }

    public async Task<bool> VerifyEmailAsync(AppUser user, string token)
    {
      var result = await _userManager.ConfirmEmailAsync(user, token);
      return result.Succeeded;
    }

    public async Task<bool> CheckPasswordAsync(AppUser user, string password)
    {
      return await _userManager.CheckPasswordAsync(user, password);
    }

    // ------------------------------------------------------
    // PASSWORD CHANGE
    // ------------------------------------------------------

    public async Task<IdentityResult> ChangePasswordAsync(AppUser user, ChangePasswordDto dto)
    {
      return await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
    }

    // ------------------------------------------------------
    // USER ME DTO
    // ------------------------------------------------------

    public async Task<UserMeDto> GetUserMeAsync(AppUser user)
    {
      return new UserMeDto
      {
        Id = user.Id,
        Email = user.Email,
        Username = user.UserName,
        CreatedAt = user.CreatedAt,
        EmailConfirmed = user.EmailConfirmed,
        Avatar = user.Avatar,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Bio = user.Bio,
        WebsiteUrl = user.WebsiteUrl,
        Premium = user.Premium,
        TwoFactorEnabled = user.TwoFactorEnabled,
        SocialLinks = await GetSocialLinksAsync(user.Id)
      };
    }

    public async Task<PublicUserDto> GetPublicUserAsync(AppUser user)
    {
      return new PublicUserDto
      {
        Id = user.Id,
        Username = user.UserName!,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Avatar = user.Avatar,
        Bio = user.Bio,
        CreatedAt = user.CreatedAt,
        Premium = user.Premium,
        WebsiteUrl = user.WebsiteUrl,
        SocialLinks = await GetSocialLinksAsync(user.Id)
      };
    }

    public async Task<List<string>> GetSocialLinksAsync(string userId)
    {
      return await _db.SocialLinks
        .Where(x => x.UserId == userId)
        .OrderBy(x => x.SortOrder)
        .Select(x => x.Url)
        .ToListAsync();
    }

    public async Task<bool> UpdateSocialLinksAsync(AppUser user, SocialLinksUpdateDto dto)
    {
      var existing = await _db.SocialLinks
        .Where(x => x.UserId == user.Id)
        .ToListAsync();

      _db.SocialLinks.RemoveRange(existing);

      var newLinks = dto.Urls
        .Where(u => !string.IsNullOrWhiteSpace(u))
        .Take(4)
        .Select((url, index) => new SocialLink
        {
          UserId = user.Id,
          Url = url.Trim(),
          SortOrder = index
        });

      await _db.SocialLinks.AddRangeAsync(newLinks);
      await _db.SaveChangesAsync();

      return true;
    }
  }
}
