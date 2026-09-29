

using Entry.Auth.Data;
using Microsoft.EntityFrameworkCore;

namespace Entry.Auth.Middlewares
{
  public class SessionValidationMiddleware
  {
    private readonly RequestDelegate _next;

    public SessionValidationMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, AppDbContext db)
    {
      if(context.User.Identity?.IsAuthenticated == true)
      {
        var sidClaim = context.User.FindFirst("sid")?.Value;

        if(Guid.TryParse(sidClaim, out var sessionId))
        {
          var isRevoked = await db.UserSessions
            .Where(s => s.Id == sessionId && s.RevokedAt != null)
            .AnyAsync();

          if (isRevoked)
          {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
          }
        }
      }

      await _next(context);
    }
  }
}