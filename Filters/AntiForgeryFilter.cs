using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

using Entry.Auth.Configuration;

namespace Entry.Auth.Filters
{
  public class AntiforgeryFilter : IAsyncActionFilter
  {
    private static readonly HashSet<string> SafeMethods = new(StringComparer.OrdinalIgnoreCase)
    {
      "GET", "HEAD", "OPTIONS", "TRACE"
    };

    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<AntiforgeryFilter> _logger;

    public AntiforgeryFilter(IAntiforgery antiforgery, ILogger<AntiforgeryFilter> logger)
    {
      _antiforgery = antiforgery;
      _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
      var request = context.HttpContext.Request;

      if (SafeMethods.Contains(request.Method))
      {
        await next();
        return;
      }

      var isAnonymous = context.ActionDescriptor.EndpointMetadata
        .OfType<IAllowAnonymous>()
        .Any();

      if (isAnonymous)
      {
        await next();
        return;
      }

      // Bearer-token clients (the React Native app) aren't exposed to CSRF:
      // a browser never attaches an Authorization header on its own, so a
      // forged cross-site request can't carry one. Only skip the check when no
      // auth cookie is present - if one is, JwtBearer authenticates with the
      // cookie (see AddJwtAuthentication), and the cookie is exactly what CSRF
      // protection exists for.
      var hasBearerHeader = request.Headers.Authorization.ToString()
        .StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
      var hasAuthCookie = request.Cookies.ContainsKey("accessToken")
        || request.Cookies.ContainsKey("refreshToken");

      if (hasBearerHeader && !hasAuthCookie)
      {
        await next();
        return;
      }

      // Kolla headern innan vi ens anropar ramverket. Om vi hoppar över det
      // här och headern saknas, faller ValidateRequestAsync tillbaka på att
      // läsa Request.Form - vilket kastar ett oskyddat InvalidOperationException
      // för JSON-requests (fel Content-Type) och kraschar med 500 istället
      // för att ge ett rent 403-svar.
      if (!request.Headers.ContainsKey(CsrfConstants.HeaderName))
      {
        _logger.LogInformation(
          "CSRF check failed: missing {Header} header for {Method} {Path}",
          CsrfConstants.HeaderName, request.Method, request.Path);

        context.Result = Forbidden();
        return;
      }

      try
      {
        await _antiforgery.ValidateRequestAsync(context.HttpContext);
      }
      catch (AntiforgeryValidationException ex)
      {
        // Förväntat: användarens token saknas/är fel/utgången. Vanligt "brus"
        // (t.ex. gamla flikar, race vid token-rotation) - logga lågt.
        _logger.LogInformation(ex,
          "CSRF validation failed for {Method} {Path}", request.Method, request.Path);

        context.Result = Forbidden();
        return;
      }
      catch (Exception ex)
      {
        // Oväntat: något annat gick sönder i ramverket (t.ex. trasig
        // DataProtection-nyckelring, felkonfigurerad cookie). Fortfarande
        // ett rent 403 utåt, men loggat som en varning så det syns i drift
        // och inte förväxlas med vanliga CSRF-avslag.
        _logger.LogWarning(ex,
          "Unexpected error during CSRF validation for {Method} {Path}", request.Method, request.Path);

        context.Result = Forbidden();
        return;
      }

      await next();
    }

    private static ObjectResult Forbidden() =>
      new(new { message = "Invalid or missing CSRF token.", code = "CSRF_TOKEN_INVALID" })
      {
        StatusCode = StatusCodes.Status403Forbidden
      };
  }
}
