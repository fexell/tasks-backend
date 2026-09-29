using Microsoft.AspNetCore.Identity;

namespace Entry.Auth.Configuration
{
  public static class IdentityConfig
  {
    public static void ConfigureIdentityOptions(IdentityOptions options)
    {
      options.Password.RequireDigit = true;
      options.Password.RequireLowercase = true;
      options.Password.RequireUppercase = true;
      options.Password.RequireNonAlphanumeric = true;
      options.Password.RequiredLength = 12;
      options.Password.RequiredUniqueChars = 4;

      options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
      options.Lockout.MaxFailedAccessAttempts = 5;
      options.Lockout.AllowedForNewUsers = true;

      options.User.RequireUniqueEmail = true;
      options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

      options.SignIn.RequireConfirmedEmail = true;
      options.SignIn.RequireConfirmedAccount = true;
      options.SignIn.RequireConfirmedPhoneNumber = false;
    }
  }
}
