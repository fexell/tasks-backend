using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Entry.Auth.Models;

namespace Entry.Auth.Services
{
  public class EmailService : IEmailService
  {
    private readonly HttpClient _http;
    private readonly IConfiguration _config;
    private readonly string _apiKey;

    public EmailService(IConfiguration config, HttpClient http)
    {
      _config = config;
      _http = http;
      _apiKey = config["Resend:ApiKey"]
        ?? throw new Exception("Missing Resend API key");
    }

    public async Task SendAsync(string to, string subject, string htmlBody)
    {
      var payload = new
      {
        from = "no-reply@audwio.com",
        to = new[] { to },
        subject,
        html = htmlBody
      };

      const int maxRetries = 3;

      for (int attempt = 1; attempt <= maxRetries; attempt++)
      {
        try
        {
          using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

          var json = JsonSerializer.Serialize(payload);
          using var content = new StringContent(json, Encoding.UTF8, "application/json");

          _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _apiKey);

          var response = await _http.PostAsync(
            "https://api.resend.com/emails",
            content,
            cts.Token
          );

          if (response.IsSuccessStatusCode)
            return;

          var error = await response.Content.ReadAsStringAsync();

          if (attempt == maxRetries)
            throw new Exception($"Failed to send email after {maxRetries} attempts: {error}");

          await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)));
        }
        catch (TaskCanceledException)
        {
          if (attempt == maxRetries)
            throw new Exception($"Email sending timed out after {maxRetries} attempts.");

          await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)));
        }
        catch (Exception ex)
        {
          if (attempt == maxRetries)
            throw new Exception($"Failed to send email after {maxRetries} attempts: {ex.Message}");

          await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)));
        }
      }
    }
  }
}
