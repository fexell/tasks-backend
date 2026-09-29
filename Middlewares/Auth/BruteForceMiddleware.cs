using System.Collections.Concurrent;
using System.Net.Mime;
using System.Text.Json;

namespace Entry.Auth.Middlewares
{
  public class BruteForceMiddleware
  {
    private readonly RequestDelegate _next;
    private readonly ILogger<BruteForceMiddleware> _logger;

    private static readonly ConcurrentDictionary<string, List<DateTime>> IpAttempts = new();
    private static readonly ConcurrentDictionary<string, List<DateTime>> EmailAttempts = new();
    private static readonly ConcurrentDictionary<string, DateTime> BlockedIps = new();

    private const int IpLimit = 20;
    private static readonly TimeSpan IpWindow = TimeSpan.FromMinutes(5);

    private const int EmailLimit = 10;
    private static readonly TimeSpan EmailWindow = TimeSpan.FromMinutes(10);

    private static readonly TimeSpan BlockDuration = TimeSpan.FromMinutes(10);

    public BruteForceMiddleware(RequestDelegate next, ILogger<BruteForceMiddleware> logger)
    {
      _next = next;
      _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
      var path = context.Request.Path.Value?.ToLowerInvariant();

      // NOTE: match a path *segment*, not just a prefix - "/auth" would otherwise
      // also match "/authors" or "/auth-docs".
      if (path is not null && (path == "/auth" || path.StartsWith("/auth/", StringComparison.Ordinal)))
      {
        // NOTE: if this app runs behind a reverse proxy/load balancer (nginx,
        // Cloudflare, etc.), RemoteIpAddress will be the proxy's IP for every
        // request, not the real client's - which means every visitor shares
        // one rate-limit bucket. Fix that with app.UseForwardedHeaders() configured
        // with the proxy's known IP/network (not by trusting a raw X-Forwarded-For
        // header here, which anyone can spoof if the proxy isn't enforcing it).
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (BlockedIps.TryGetValue(ip, out var blockedUntil))
        {
          if (blockedUntil > DateTime.UtcNow)
          {
            await WriteTooManyRequests(context, "Too many requests. Please try again later.", "IP_BLOCKED");
            return;
          }

          BlockedIps.TryRemove(ip, out _);
        }

        LogAttempt(IpAttempts, ip);

        if (IsLimitExceeded(IpAttempts, ip, IpLimit, IpWindow))
        {
          BlockedIps[ip] = DateTime.UtcNow.Add(BlockDuration);

          _logger.LogWarning("IP {Ip} blocked for {Minutes} min after exceeding {Limit} requests to {Path}",
            ip, BlockDuration.TotalMinutes, IpLimit, path);

          await WriteTooManyRequests(context, "Too many requests from this IP. Please try again later.", "IP_RATE_LIMITED");
          return;
        }

        if (context.Request.Method == "POST" && context.Request.ContentType?.Contains("application/json") == true)
        {
          context.Request.EnableBuffering();

          using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
          var body = await reader.ReadToEndAsync();
          context.Request.Body.Position = 0;

          var email = ExtractEmail(body);
          if (email is not null)
          {
            LogAttempt(EmailAttempts, email);

            if (IsLimitExceeded(EmailAttempts, email, EmailLimit, EmailWindow))
            {
              _logger.LogWarning("Email attempt limit exceeded for {Path} (ip {Ip})", path, ip);

              await WriteTooManyRequests(context, "Too many attempts for this account. Please try again later.", "EMAIL_RATE_LIMITED");
              return;
            }
          }
        }
      }

      await _next(context);
    }

    private static async Task WriteTooManyRequests(HttpContext context, string message, string code)
    {
      context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
      context.Response.ContentType = MediaTypeNames.Application.Json;

      await context.Response.WriteAsync(JsonSerializer.Serialize(new { message, code }));
    }

    private static void LogAttempt(ConcurrentDictionary<string, List<DateTime>> dict, string key)
    {
      var now = DateTime.UtcNow;

      var list = dict.GetOrAdd(key, _ => new List<DateTime>());

      lock (list)
      {
        list.Add(now);
      }
    }

    private static bool IsLimitExceeded(
      ConcurrentDictionary<string, List<DateTime>> dict,
      string key,
      int limit,
      TimeSpan window
    )
    {
      if (!dict.TryGetValue(key, out var list))
      {
        return false;
      }

      var cutoff = DateTime.UtcNow - window;

      lock (list)
      {
        list.RemoveAll(t => t < cutoff);

        // Opportunistic cleanup: drop the key entirely once its window is
        // empty, so IpAttempts/EmailAttempts don't grow forever for one-off
        // visitors. Doesn't catch every case (an entry only gets swept the
        // next time that same key is checked) - a background sweep like your
        // AuthDataRetentionService would be needed for a full fix.
        if (list.Count == 0)
        {
          dict.TryRemove(key, out _);
          return false;
        }

        return list.Count >= limit;
      }
    }

    private static string? ExtractEmail(string json)
    {
      try
      {
        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.TryGetProperty("email", out var emailProp))
        {
          return emailProp.GetString()?.Trim().ToLowerInvariant();
        }
      }
      catch (JsonException) { }

      return null;
    }
  }
}
