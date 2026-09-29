

namespace Entry.Auth.Configuration
{
  public static class CsrfConstants
  {
    // Header som frontend måste skicka på varje muterande request.
    // Refereras både av AddAppAntiforgery (Antiforgery.HeaderName) och
    // AntiforgeryFilter (kollar headern manuellt innan validering) -
    // håll den här som enda källan för att undvika att de driftar isär.
    public const string HeaderName = "X-CSRF-TOKEN";
  }
}
