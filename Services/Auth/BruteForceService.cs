using Microsoft.EntityFrameworkCore;

using Entry.Auth.Data;
using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class BruteForceService : IBruteForceService
  {
    private readonly AppDbContext _db;

    private static readonly TimeSpan IpWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan EmailWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan UserWindow = TimeSpan.FromMinutes(5);

    private const int IpLimit = 20;
    private const int EmailLimit = 10;
    private const int UserLimit = 5;

    public BruteForceService(AppDbContext db)
    {
      _db = db;
    }

    public async Task LogAsync(
      string endpoint,
      string ip,
      string? email,
      string? userId,
      bool success,
      AuthFailureReason failureReason = AuthFailureReason.None,
      string? userAgent = null
    )
    {
      var attempt = new AuthAttempt
      {
        Endpoint = endpoint,
        IpAddress = ip,
        UserAgent = userAgent,
        Email = email?.Trim().ToUpperInvariant(),
        UserId = userId,
        Success = success,
        FailureReason = success ? AuthFailureReason.None : failureReason,
        Timestamp = DateTime.UtcNow
      };

      _db.AuthAttempts.Add(attempt);
      await _db.SaveChangesAsync();
    }

    public async Task<bool> IsIpBlockedAsync(string ip)
    {
      return await IsBlockedAsync(x => x.IpAddress == ip, IpWindow, IpLimit);
    }

    public async Task<bool> IsEmailBlockedAsync(string email)
    {
      var normalizedEmail = email.Trim().ToUpperInvariant();
      return await IsBlockedAsync(x => x.Email == normalizedEmail, EmailWindow, EmailLimit);
    }

    public async Task<bool> IsUserBlockedAsync(string userId)
    {
      return await IsBlockedAsync(x => x.UserId == userId, UserWindow, UserLimit);
    }

    private async Task<bool> IsBlockedAsync(
      System.Linq.Expressions.Expression<Func<AuthAttempt, bool>> predicate,
      TimeSpan window,
      int limit
    )
    {
      var cutoff = DateTime.UtcNow - window;

      var count = await _db.AuthAttempts
        .Where(predicate)
        .Where(x => !x.Success && x.Timestamp >= cutoff)
        .CountAsync();

      return count >= limit;
    }
  }
}
