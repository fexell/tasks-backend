using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Entry.Auth.Data;

namespace Entry.Auth.Services
{
  public class AuthDataRetentionService : BackgroundService
  {
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AuthDataRetentionService> _logger;
    private readonly IConfiguration _config;

    private static readonly TimeSpan InitialDelay = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan RunInterval = TimeSpan.FromHours(24);
    private const int MinRetentionDays = 1;

    public AuthDataRetentionService(
      IServiceScopeFactory scopeFactory,
      ILogger<AuthDataRetentionService> logger,
      IConfiguration config
    )
    {
      _scopeFactory = scopeFactory;
      _logger = logger;
      _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
      _logger.LogInformation("AuthDataRetentionService started.");

      try
      {
        await Task.Delay(InitialDelay, stoppingToken);
      }
      catch (TaskCanceledException)
      {
        return;
      }

      using var timer = new PeriodicTimer(RunInterval);

      do
      {
        try
        {
          await CleanupAsync(stoppingToken);
        }
        catch (Exception ex)
        {
          _logger.LogError(ex, "Unexpected error while cleaning up auth data.");
        }
      }
      while (await WaitForNextTickAsync(timer, stoppingToken));

      _logger.LogInformation("AuthDataRetentionService stopped.");
    }

    private static async Task<bool> WaitForNextTickAsync(PeriodicTimer timer, CancellationToken stoppingToken)
    {
      try
      {
        return await timer.WaitForNextTickAsync(stoppingToken);
      }
      catch (OperationCanceledException)
      {
        return false;
      }
    }

    private async Task CleanupAsync(CancellationToken stoppingToken)
    {
      using var scope = _scopeFactory.CreateScope();
      var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

      var authAttemptsDays = GetRetentionDays("DataRetention:AuthAttemptsDays", defaultValue: 30);
      var riskAssessmentsDays = GetRetentionDays("DataRetention:LoginRiskAssessmentsDays", defaultValue: 90);

      var deletedAttempts = await TryDeleteAsync(
        () => db.AuthAttempts
          .Where(x => x.Timestamp < DateTime.UtcNow.AddDays(-authAttemptsDays))
          .ExecuteDeleteAsync(stoppingToken),
        "AuthAttempts"
      );

      var deletedAssessments = await TryDeleteAsync(
        () => db.LoginRiskAssessments
          .Where(x => x.Timestamp < DateTime.UtcNow.AddDays(-riskAssessmentsDays))
          .ExecuteDeleteAsync(stoppingToken),
        "LoginRiskAssessments"
      );

      if (deletedAttempts > 0 || deletedAssessments > 0)
      {
        _logger.LogInformation(
          "Data retention cleanup: removed {AuthAttempts} AuthAttempts (older than {AuthDays}d) and {RiskAssessments} LoginRiskAssessments (older than {RiskDays}d).",
          deletedAttempts,
          authAttemptsDays,
          deletedAssessments,
          riskAssessmentsDays
        );
      }
    }

    private int GetRetentionDays(string configKey, int defaultValue)
    {
      var value = _config.GetValue<int?>(configKey) ?? defaultValue;

      if (value < MinRetentionDays)
      {
        _logger.LogWarning(
          "Configured retention value for {ConfigKey} ({Value}) is below the minimum of {MinDays}d. Falling back to {DefaultValue}d.",
          configKey,
          value,
          MinRetentionDays,
          defaultValue
        );

        return defaultValue;
      }

      return value;
    }

    private async Task<int> TryDeleteAsync(Func<Task<int>> deleteAction, string tableName)
    {
      try
      {
        return await deleteAction();
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Failed to clean up expired records from {TableName}.", tableName);
        return 0;
      }
    }
  }
}
