using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;

using Entry.Auth.Extensions;
using Entry.Auth.Filters;
using Entry.Auth.Middlewares;
using Entry.Auth.Services;

var builder = WebApplication.CreateBuilder(args);
var supportedCultures = new[] { "en", "sv" };

// -----------------------------------------------------
// CORS
// -----------------------------------------------------
// Origins come from config so each environment (dev/staging/prod) can
// point at its own frontend without touching code. "Cors:AllowedOrigins"
// supports multiple origins (e.g. www + app subdomains); if it's not set,
// falls back to the single "AppUrls:FrontendBaseUrl" already used
// elsewhere in the app (email links etc.), which appsettings.json sets to
// http://localhost:3000 for local dev.
var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();

if (corsOrigins == null || corsOrigins.Length == 0)
{
    var frontendUrl = builder.Configuration["AppUrls:FrontendBaseUrl"];
    corsOrigins = string.IsNullOrWhiteSpace(frontendUrl)
        ? Array.Empty<string>()
        : new[] { frontendUrl };
}

if (corsOrigins.Length == 0)
{
    throw new InvalidOperationException(
        "No CORS origins configured. Set \"AppUrls:FrontendBaseUrl\" or \"Cors:AllowedOrigins\" in appsettings.");
}

builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy.WithOrigins(corsOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// -----------------------------------------------------
// Services
// -----------------------------------------------------
builder.Services
    .AddAppDbContext(builder.Configuration)
    .AddAppIdentity()
    .AddJwtAuthentication(builder.Configuration)
    .AddAppServices()
    .AddAppAntiforgery(builder.Environment)
    .AddAppAuthorization();

// builder.Services.AddHttpClient<IEmailService, EmailService>();

builder.Services.AddScoped<AppDbContextSeeder>();

builder.Services.AddControllers(options =>
{
    options.Filters.Add<ValidationFilter>();
    options.Filters.Add<AntiforgeryFilter>();
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// builder.Services.AddHostedService<EmailVerificationRefreshService>();

// -----------------------------------------------------
// Localization
// -----------------------------------------------------
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var cultures = supportedCultures.Select(c => new CultureInfo(c)).ToList();

    options.DefaultRequestCulture = new RequestCulture("en");
    options.SupportedCultures = cultures;
    options.SupportedUICultures = cultures;

    options.RequestCultureProviders.Insert(0, new CustomRequestCultureProvider(async context =>
    {
        var lang = context.Request.Cookies["lang"];

        if(lang is "en" or "sv")
            return new ProviderCultureResult(lang);

        return null;
    }));
});

// -----------------------------------------------------
// Rate Limiter
// -----------------------------------------------------

builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "application/json";
        context.HttpContext.Response.Headers.RetryAfter = "60";

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            message = "Too many requests. Please try again later.",
            code = "RATE_LIMITED"
        }, token);
    };

    options.AddPolicy("AuthPolicy", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: key => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 10,                 // 10 försök
                Window = TimeSpan.FromMinutes(1), // per minut
                SegmentsPerWindow = 2,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

// -----------------------------------------------------
// Build
// -----------------------------------------------------
var app = builder.Build();

// -----------------------------------------------------
// Forwarded headers — MUST run before anything else.
// -----------------------------------------------------
// ForwardedHeadersMiddleware rewrites HttpContext.Connection.RemoteIpAddress
// (and the request scheme) based on X-Forwarded-For/X-Forwarded-Proto.
// Every place in this app that reads RemoteIpAddress directly — the rate
// limiter partition key, BruteForceMiddleware, login attempt logging,
// LoginRiskService's geolocation — depends on this running first and
// being configured correctly, or it'll see the reverse proxy's IP for
// every single request instead of the real client's.
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};

var knownProxies = builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? Array.Empty<string>();
var knownNetworks = builder.Configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? Array.Empty<string>();

foreach (var proxy in knownProxies)
{
    if (IPAddress.TryParse(proxy, out var proxyIp))
        forwardedHeadersOptions.KnownProxies.Add(proxyIp);
}

foreach (var network in knownNetworks)
{
    var parts = network.Split('/');

    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var networkIp) && int.TryParse(parts[1], out var prefixLength))
        forwardedHeadersOptions.KnownIPNetworks.Add(new System.Net.IPNetwork(networkIp, prefixLength));
}

if (knownProxies.Length == 0 && knownNetworks.Length == 0 && !app.Environment.IsDevelopment())
{
    // No trusted proxy/network configured outside local dev. Clearing
    // these makes the middleware trust X-Forwarded-For from *any*
    // upstream, which is only safe if whatever sits in front of this app
    // (cloud load balancer, ingress, etc.) is itself the thing setting
    // that header and nothing else can reach this app directly. If a
    // client could hit this app without going through your proxy, they
    // could spoof X-Forwarded-For and bypass brute-force/rate limiting
    // entirely — set ForwardedHeaders:KnownProxies or :KnownNetworks in
    // appsettings for that environment instead of relying on this.
    forwardedHeadersOptions.KnownIPNetworks.Clear();
    forwardedHeadersOptions.KnownProxies.Clear();
}

app.UseForwardedHeaders(forwardedHeadersOptions);

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// CORS must run before anything that can short-circuit the pipeline
// (like BruteForceMiddleware returning a 429 directly). Middleware that
// runs before UseCors never gets its response headers touched by it - so
// a rate-limited response would arrive at the browser without an
// Access-Control-Allow-Origin header and get silently blocked as a CORS
// failure instead of being readable as a 429 by the frontend.
app.UseCors("Frontend");

// Brute force protection
app.UseMiddleware<BruteForceMiddleware>();

// Silent refresh BEFORE authentication
// app.UseMiddleware<SilentRefreshMiddleware>();

var locOptions = app.Services.GetRequiredService<IOptions<RequestLocalizationOptions>>();
app.UseRequestLocalization(locOptions.Value);

// Rate limiter
app.UseRateLimiter();

app.UseAuthentication();
app.UseMiddleware<SessionValidationMiddleware>();
app.UseAuthorization();

app.MapControllers();

try
{
    using (var scope = app.Services.CreateScope())
    {
        var seeder = scope.ServiceProvider.GetRequiredService<AppDbContextSeeder>();
        await seeder.SeedAsync();
    }

    Console.WriteLine("Seeding complete.");
}
catch(Exception ex)
{
    Console.WriteLine($"Error during database seeding: {ex.Message}");
    Console.WriteLine($"Stack trace: {ex.StackTrace}");
}

app.Run();
