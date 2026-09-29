using Microsoft.AspNetCore.Identity;

using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class EmailChangeService : IEmailChangeService
  {
    private readonly UserManager<AppUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    public EmailChangeService(
      UserManager<AppUser> userManager,
      IEmailService emailService,
      IConfiguration config,
      IWebHostEnvironment env
    )
    {
      _userManager = userManager;
      _emailService = emailService;
      _config = config;
      _env = env;
    }

    public async Task<EmailChangeResult> RequestEmailChangeAsync(AppUser user, string newEmail, string password)
    {
      var passwordValid = await _userManager.CheckPasswordAsync(user, password);
      if(!passwordValid) return EmailChangeResult.InvalidPassword;

      if(string.Equals(newEmail, user.Email, StringComparison.OrdinalIgnoreCase))
        return EmailChangeResult.SameEmail;

      var exisiting = await _userManager.FindByEmailAsync(newEmail);
      if(exisiting != null) return EmailChangeResult.EmailInUse;

      var token = await _userManager.GenerateChangeEmailTokenAsync(user, newEmail);

      var baseUrl = _env.IsDevelopment() ? "http://localhost:3000" : _config["AppUrls:FrontendBaseUrl"];
      var link = $"{baseUrl}/account/confirm-email-change" +
        $"?userId={user.Id}" +
        $"&newEmail={Uri.EscapeDataString(newEmail)}" +
        $"&token={Uri.EscapeDataString(token)}";

      if(_env.IsDevelopment())
      {
        Console.WriteLine($"EMAIL CHANGE TOKEN:");
        Console.WriteLine(token);
        Console.WriteLine($"EMAIL CHANGE LINK:");
        Console.WriteLine(link);
      }

      await _emailService.SendAsync(
        newEmail,
        "Confirm your new email address",
        $@"<p>You requested to change the email address on your account to this one.</p>
        <p><a href='{link}'>Click here to confirm the change</a></p>
        <p>If you didn't request this, you can safely ignore this email."
      );

      return EmailChangeResult.Success;
    }

    public async Task<bool> ConfirmEmailChangeAsync(AppUser user, string newEmail, string token)
    {
      var result = await _userManager.ChangeEmailAsync(user, newEmail, token);
      return result.Succeeded;
    }
  }
}