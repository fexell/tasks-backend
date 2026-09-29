using System.Security.Cryptography;

namespace Entry.Auth.Utils
{
  public static class CookieHelper
  {
    public static void Set(HttpResponse response, string key, string value, TimeSpan? maxAge = null, CookieOptions? options = null)
    {
      var opts = options ?? new CookieOptions
      {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        MaxAge = maxAge
      };

      response.Cookies.Append(key, value, opts);
    }

    public static string? Get(HttpRequest request, string key)
    {
      return request.Cookies.TryGetValue(key, out var value) ? value : null;
    }

    public static void Delete(HttpResponse response, string key)
    {
      response.Cookies.Delete(key);
    }

    public static string Generate(string prefix)
    {
      var bytes = RandomNumberGenerator.GetBytes(16);
      var hex = Convert.ToHexString(bytes).ToLowerInvariant();
      return $"{prefix}-{hex}";
    }

    public static string SetRandom(
      HttpResponse response,
      string prefix,
      string value,
      TimeSpan? maxAge = null,
      CookieOptions? options = null
    )
    {
      var name = Generate(prefix);
      Set(response, name, value, maxAge, options);
      return name;
    }

    public static string? GetRandom(HttpRequest request, string prefix)
    {
      var match = request.Cookies.Keys.FirstOrDefault(k => k.StartsWith(prefix + "-", StringComparison.Ordinal));
      return match is null ? null : request.Cookies[match];
    }

    public static void DeleteRandom(HttpResponse response, HttpRequest request, string prefix)
    {
      var match = request.Cookies.Keys.FirstOrDefault(k => k.StartsWith(prefix + "-", StringComparison.Ordinal));
      if(match is not null)
        response.Cookies.Delete(match);
    }
  }
}
