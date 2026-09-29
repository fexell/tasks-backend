using System.Security.Cryptography;

namespace Entry.Auth.Utils
{
  public static class TokenGenerator
  {
    public static string GenerateRandomToken(int length = 60)
    {
      var bytes = RandomNumberGenerator.GetBytes(length);
      return Convert.ToBase64String(bytes);
    }
  }
}
