using System.Security.Claims;

namespace Entry.Auth.Extensions
{
  public static class ClaimsPrincipalExtensions
  {
    /// <summary>
    /// Gets the authenticated user's ID from claims.
    /// Throws if called on a principal that isn't authenticated with the expected
    /// claim present - this should only happen due to a missing [Authorize] attribute
    /// or a token issued without the ID claim, not from normal user input.
    /// </summary>
    public static string GetUserId(this ClaimsPrincipal user)
    {
      return user.FindFirstValue(ClaimTypes.NameIdentifier)
          ?? user.FindFirstValue("sub")
          ?? user.FindFirstValue("uid")
          ?? throw new InvalidOperationException(
               "User ID claim missing. Endpoint may be missing [Authorize], or the token was issued without a NameIdentifier/sub/uid claim.");
    }
  }
}
