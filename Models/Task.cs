using System;

using Entry.Auth.Models;

namespace TasksApp.Models
{
  public class Task
  {
    public int Id { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public bool IsCompleted { get; set; }
    public DateTime? DueDate { get; set; }
    public string? FileUrl { get; set; }
    public string? FileName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Foreign key
    public string AppUserId { get; set; }
    public AppUser AppUser { get; set; }
  }
}