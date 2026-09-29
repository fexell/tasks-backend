using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;

using Entry.Auth.Services;
using Entry.Auth.Models;
using Entry.Auth.Data;
using Entry.Auth.Utils;

namespace Entry.Auth.Middlewares
{
  public class SilentRefreshMiddleware
  {
    private readonly RequestDelegate _next;

    public SilentRefreshMiddleware(RequestDelegate next)
    {
      _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
      var endpoint = context.GetEndpoint();

      if (endpoint is null || endpoint.Metadata.GetMetadata<IAllowAnonymous>() != null)
      {
        await _next(context);
        return;
      }

      var authService = context.RequestServices.GetRequiredService<IAuthService>();
      var userManager = context.RequestServices.GetRequiredService<UserManager<AppUser>>();
      var db = context.RequestServices.GetRequiredService<AppDbContext>();

      var accessToken = CookieHelper.Get(context.Request, "accessToken");
      var refreshToken = CookieHelper.Get(context.Request, "refreshToken");

      // No tokens → continue
      if (string.IsNullOrEmpty(accessToken) && string.IsNullOrEmpty(refreshToken))
      {
        await _next(context);
        return;
      }

      var handler = new JwtSecurityTokenHandler();
      string? userId = null;

      // Try read access token (no validation here)
      try
      {
        var jwt = handler.ReadJwtToken(accessToken);
        userId = jwt.Subject;

        var existingUser = await userManager.FindByIdAsync(userId);
        if (existingUser != null)
        {
          // Access token is valid → continue
          await _next(context);
          return;
        }
      }
      catch
      {
        // Access token invalid → try refresh
      }

      // No refresh token → continue
      if (string.IsNullOrEmpty(refreshToken))
      {
        await _next(context);
        return;
      }

      // Read refresh token from DB
      var refreshEntity = await db.RefreshTokens
        .FirstOrDefaultAsync(x => x.Token == refreshToken);

      if (refreshEntity == null || refreshEntity.Revoked || refreshEntity.ExpiresAt < DateTime.UtcNow)
      {
        CookieHelper.Delete(context.Response, "accessToken");
        CookieHelper.Delete(context.Response, "refreshToken");
        await _next(context);
        return;
      }

      var refreshUser = await userManager.FindByIdAsync(refreshEntity.UserId);
      if (refreshUser == null)
      {
        CookieHelper.Delete(context.Response, "accessToken");
        CookieHelper.Delete(context.Response, "refreshToken");
        await _next(context);
        return;
      }

      // Perform silent refresh via AuthService
      var result = await authService.SilentRefreshAsync(refreshUser, refreshToken);

      if (!result.Success)
      {
        CookieHelper.Delete(context.Response, "accessToken");
        CookieHelper.Delete(context.Response, "refreshToken");
        await _next(context);
        return;
      }

      // Gör den nya token:en tillgänglig för RESTEN av denna request
      context.Items["AccessToken"] = result.AccessToken;

      CookieHelper.Set(context.Response, "accessToken", result.AccessToken!, TimeSpan.FromHours(1));
      CookieHelper.Set(context.Response, "refreshToken", result.RefreshToken!, TimeSpan.FromDays(30));

      await _next(context);
    }
  }
}
