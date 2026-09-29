

namespace Entry.Auth.Services
{
  public interface IFrontendUrlProvider
  {
    string GetBaseUrl();
    string BuildUrl(string path);
  }
}