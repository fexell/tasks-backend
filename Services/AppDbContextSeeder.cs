using Microsoft.AspNetCore.Identity;

using Entry.Auth.Models;
using Entry.Auth.Data;
using Task = TasksApp.Models.Task;

namespace Entry.Auth.Services
{
  public class AppDbContextSeeder
  {
    private readonly AppDbContext _context;
    private readonly UserManager<AppUser> _userManager;

    public AppDbContextSeeder(AppDbContext context, UserManager<AppUser> userManager)
    {
      _context = context;
      _userManager = userManager;
    }

    public async System.Threading.Tasks.Task SeedAsync()
    {
      var demoUser = await _userManager.FindByEmailAsync("demo@example.com");

      if(demoUser == null)
      {
        var user = new AppUser
        {
          UserName = "Demo",
          Email = "demo@example.com",
          FirstName = "Demo",
          LastName = "Användare",
          EmailConfirmed = true,
          CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, "DemoPassword123!");

        if(result.Succeeded)
        {
          var userId = user.Id;

          _context.Tasks.AddRange(new[]
          {
            new Task
            {
              Title = "Välkommen till Tasks App!",
              Description = "Det  här är en demo-uppgift. Du kan redigera, markera som klar, eller ladda upp en fil.",
              IsCompleted = false,
              DueDate = DateTime.UtcNow.AddDays(3),
              AppUserId = userId,
              CreatedAt = DateTime.UtcNow,
              UpdatedAt = DateTime.UtcNow
            },
            new Task
            {
              Title = "Lägg till en ny uppgift",
              Description = "Klicka på 'Ny uppgift' för att skapa en ny task.",
              IsCompleted = true,
              DueDate = DateTime.UtcNow.AddDays(1),
              AppUserId = userId,
              CreatedAt = DateTime.UtcNow,
              UpdatedAt = DateTime.UtcNow
            }
          });

          await _context.SaveChangesAsync();
          Console.WriteLine("Demo-konto och uppgifter har skapats.");
        }
        else
        {
          Console.WriteLine("Kund inte skapa demo-konto.");
        }
      }
    }
  }
}