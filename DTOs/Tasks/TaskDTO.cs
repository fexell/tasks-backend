

namespace TasksApp.DTOs
{
  public class TaskDTO
  {
    public int Id { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public bool IsCompleted { get; set; }
    public DateTime? DueDate { get; set; }
    public string FileUrl { get; set; }
    public string FileName { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
  }

  public class CreateTaskDTO
  {
    public string Title { get; set; }
    public string Description { get; set; }
    public DateTime? DueDate { get; set; }
  }

  public class UpdateTaskDTO
  {
    public string Title { get; set; }
    public string Description { get; set; }
    public bool IsCompleted { get; set; }
    public DateTime? DueDate { get; set; }
  }
}