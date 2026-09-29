using Microsoft.Extensions.Hosting;

namespace Entry.Auth.Services
{
  public class FrontendUrlProvider : IFrontendUrlProvider
  {
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    private const string DevelopmentBaseUrl = "http://localhost:3000";

    public FrontendUrlProvider(IConfiguration config, IWebHostEnvironment env)
    {
      _config = config;
      _env = env;
    }

    public string GetBaseUrl()
    {
      if (_env.IsDevelopment())
      {
        return _config["AppUrls:FrontendBaseUrl"] ?? DevelopmentBaseUrl;
      }

      var configuredUrl = _config["AppUrls:FrontendBaseUrl"];

      if (string.IsNullOrWhiteSpace(configuredUrl))
      {
        throw new InvalidOperationException(
          "AppUrls:FrontendBaseUrl is not configured. This is required outside of development."
        );
      }

      return configuredUrl;
    }

    public string BuildUrl(string path)
    {
      var baseUrl = GetBaseUrl().TrimEnd('/');
      var trimmedPath = path.TrimStart('/');

      return $"{baseUrl}/{trimmedPath}";
    }
  }
}