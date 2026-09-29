using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Npgsql.EntityFrameworkCore.PostgreSQL;

using Entry.Auth.Configuration;
using Entry.Auth.Data;
using Entry.Auth.Models;
using Entry.Auth.Services;

namespace Entry.Auth.Extensions
{
  public static class ServiceCollectionExtensions
  {
    public static IServiceCollection AddAppDbContext(
      this IServiceCollection services,
      IConfiguration config
    )
    {
      services.AddDbContext<AppDbContext>(options =>
        options.UseNpgsql(
          config.GetConnectionString("Default"),
          npgsql =>
          {
            npgsql.EnableRetryOnFailure(
              maxRetryCount: 5,
              maxRetryDelay: TimeSpan.FromSeconds(10),
              errorCodesToAdd: null
            );

            npgsql.MigrationsAssembly(typeof(AppDbContext).Assembly.FullName);
          }
        )
      );

      return services;
    }

    public static IServiceCollection AddAppIdentity(
      this IServiceCollection services
    )
    {
      services.AddIdentity<AppUser, IdentityRole>(options =>
      {
        IdentityConfig.ConfigureIdentityOptions(options);
      })
      .AddRoles<IdentityRole>()
      .AddEntityFrameworkStores<AppDbContext>()
      .AddDefaultTokenProviders();

      return services;
    }

    public static IServiceCollection AddJwtAuthentication(
      this IServiceCollection services,
      IConfiguration config
    )
    {
      var jwtKey = config["Jwt:Key"]
        ?? throw new InvalidOperationException("Missing required configuration value 'Jwt:Key'.");

      var key = Encoding.UTF8.GetBytes(jwtKey);

      services.AddAuthentication(options =>
      {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
      })
      .AddJwtBearer(options =>
      {
        options.SaveToken = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
          ValidateIssuer = true,
          ValidateAudience = true,
          ValidateIssuerSigningKey = true,
          ValidateLifetime = true,
          RequireExpirationTime = true,
          RequireSignedTokens = true,
          ValidateTokenReplay = true,

          ValidIssuer = config["Jwt:Issuer"],
          ValidAudience = config["Jwt:Audience"],
          IssuerSigningKey = new SymmetricSecurityKey(key),

          ClockSkew = TimeSpan.Zero,
        };

        options.Events = new JwtBearerEvents
        {
          OnMessageReceived = context =>
          {
            // Prioritera nyss-refreshad token från denna request (satt av SilentRefreshMiddleware)
            /* if (context.HttpContext.Items.TryGetValue("AccessToken", out var refreshed) && refreshed is string s)
            {
              context.Token = s;
              return Task.CompletedTask;
            } */

            if (context.Request.Cookies.TryGetValue("accessToken", out var token))
              context.Token = token;

            return Task.CompletedTask;
          },

          OnTokenValidated = context =>
          {
            var purpose = context.Principal?.FindFirst("purpose")?.Value;

            if(purpose == "2fa")
            {
              context.Fail("Invalid token type.");
            }

            return Task.CompletedTask;
          }
        };
      });

      return services;
    }

    public static IServiceCollection AddAppServices(
      this IServiceCollection services
    )
    {
      services.AddScoped<IEmailService, EmailService>();
      services.AddScoped<IUserService, UserService>();
      services.AddScoped<IAuthService, AuthService>();
      services.AddScoped<IVerificationEmailService, VerificationEmailService>();
      services.AddScoped<IEmailChangeService, EmailChangeService>();
      services.AddScoped<IPasswordResetService, PasswordResetService>();

      services.AddScoped<IJwtService, JwtService>();
      services.AddScoped<IRefreshTokenService, RefreshTokenService>();
      services.AddScoped<ITwoFactorService, TwoFactorService>();
      services.AddScoped<IBruteForceService, BruteForceService>();
      services.AddScoped<ILoginNotificationService, LoginNotificationService>();

      services.AddScoped<IFrontendUrlProvider, FrontendUrlProvider>();

      services.AddHostedService<EmailVerificationRefreshService>();
      services.AddHostedService<AuthDataRetentionService>();

      services.AddMemoryCache();

      services.AddHttpClient();

      // Typed client for LoginRiskService: short timeout so a slow/down
      // geo-IP provider can never stall the login request for long.
      services.AddHttpClient<ILoginRiskService, LoginRiskService>(client =>
      {
        client.Timeout = TimeSpan.FromSeconds(3);
      });

      return services;
    }

    public static IServiceCollection AddAppAntiforgery(
      this IServiceCollection services,
      IWebHostEnvironment env
    )
    {
      services.AddAntiforgery(options =>
      {
        // Header som frontend måste skicka på varje muterande request
        options.HeaderName = CsrfConstants.HeaderName;

        // Cookien får INTE vara httpOnly - JS behöver kunna se att den finns
        // (själva värdet i cookien används internt av Antiforgery, frontend
        // skickar aldrig cookie-värdet självt, bara token:et från /csrf-token)
        options.Cookie.Name = "XSRF-TOKEN";
        options.Cookie.HttpOnly = false;
        options.Cookie.SameSite = SameSiteMode.Lax;

        // Secure kräver HTTPS för att webbläsaren ska spara cookien alls -
        // även på localhost. I dev (vanligtvis plain http) måste den vara
        // SameAsRequest, annars sparas cookien aldrig och CSRF-valideringen
        // saknar sin ena halva på varje request.
        options.Cookie.SecurePolicy = env.IsDevelopment()
          ? CookieSecurePolicy.SameAsRequest
          : CookieSecurePolicy.Always;
      });

      return services;
    }

    public static IServiceCollection AddAppAuthorization(
      this IServiceCollection services
    )
    {
      services.AddAuthorization(options =>
      {
        options.AddPolicy("Admin", policy =>
        {
          policy.RequireRole("Admin");
        });

        options.FallbackPolicy = new AuthorizationPolicyBuilder()
          .RequireAuthenticatedUser()
          .Build();
      });

      return services;
    }
  }
}
