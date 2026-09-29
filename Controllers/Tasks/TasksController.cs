using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

using Entry.Auth.Data;
using Entry.Auth.Models;
using Entry.Auth.DTOs;

using Task = TasksApp.Models.Task;
using TasksApp.DTOs;

namespace TasksApp.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  [Authorize]
  public class TasksController : ControllerBase
  {
    private readonly AppDbContext _context;
    private readonly IWebHostEnvironment _env;

    public TasksController(
      AppDbContext context,
      IWebHostEnvironment env
    )
    {
      _context = context;
      _env = env;
    }

    private string GetUserId() => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet]
    public async Task<ActionResult<IEnumerable<TaskDTO>>> GetTasks()
    {
      var userId = GetUserId();
      var tasks = await _context.Tasks
        .Where(t => t.AppUserId == userId)
        .OrderByDescending(t => t.CreatedAt)
        .Select(t => new TaskDTO
        {
          Id = t.Id,
          Title = t.Title,
          Description = t.Description,
          IsCompleted = t.IsCompleted,
          DueDate = t.DueDate,
          FileUrl = t.FileUrl,
          FileName = t.FileName,
          CreatedAt = t.CreatedAt,
          UpdatedAt = t.UpdatedAt
        })
        .ToListAsync();

      return Ok(tasks);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<TaskDTO>> GetTask(int id)
    {
      var userId = GetUserId();
      var task = await _context.Tasks
        .FirstOrDefaultAsync(t => t.Id == id && t.AppUserId == userId);

      if(task == null)
        return NotFound(new { error = "Task not found"});

      return Ok(new TaskDTO
      {
        Id = task.Id,
        Title = task.Title,
        Description = task.Description,
        IsCompleted = task.IsCompleted,
        DueDate = task.DueDate,
        FileUrl = task.FileUrl,
        FileName = task.FileName,
        CreatedAt = task.CreatedAt,
        UpdatedAt = task.UpdatedAt
      });
    }

    [HttpPost]
    public async Task<ActionResult<TaskDTO>> CreateTask([FromBody] CreateTaskDTO dto)
    {
      if(!ModelState.IsValid)
        return BadRequest(ModelState);

      var userId = GetUserId();
      var task = new Task
      {
        Title = dto.Title,
        Description = dto.Description,
        DueDate = dto.DueDate,
        IsCompleted = false,
        AppUserId = userId,
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow
      };

      _context.Tasks.Add(task);
      await _context.SaveChangesAsync();

      return CreatedAtAction(nameof(GetTask), new { id = task.Id }, new TaskDTO
      {
        Id = task.Id,
        Title = task.Title,
        Description = task.Description,
        IsCompleted = task.IsCompleted,
        DueDate = task.DueDate,
        FileUrl = task.FileUrl,
        FileName = task.FileName,
        CreatedAt = task.CreatedAt,
        UpdatedAt = task.UpdatedAt
      });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateTask(int id, UpdateTaskDTO dto)
    {
      if(string.IsNullOrWhiteSpace(dto.Title))
      {
        ModelState.AddModelError("Title", "Title is required.");
      }

      if(!ModelState.IsValid)
        return BadRequest(ModelState);

      var userId = GetUserId();
      var task = await _context.Tasks
        .FirstOrDefaultAsync(t => t.Id == id && t.AppUserId == userId);

      if(task == null)
        return NotFound(new { error = "Task not found" });

      task.Title = dto.Title;
      task.Description = dto.Description;
      task.IsCompleted = dto.IsCompleted;
      task.DueDate = dto.DueDate;
      task.UpdatedAt = DateTime.UtcNow;

      _context.Tasks.Update(task);
      await _context.SaveChangesAsync();

      return Ok(new TaskDTO
      {
        Id = task.Id,
        Title = task.Title,
        Description = task.Description,
        IsCompleted = task.IsCompleted,
        DueDate = task.DueDate,
        FileUrl = task.FileUrl,
        FileName = task.FileName,
        CreatedAt = task.CreatedAt,
        UpdatedAt = task.UpdatedAt
      });
    }

    [HttpPost("{id}/upload")]
    public async Task<IActionResult> UploadFile(int id, IFormFile file)
    {
      if(file == null || file.Length == 0)
        return BadRequest(new { error = "No file uploaded" });

      // Allowed MIME types (must match frontend validation)
      var allowedTypes = new[]
      {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
        "application/msword", // .doc
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
        "application/vnd.ms-excel", // .xls
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
        "application/vnd.ms-powerpoint", // .ppt
        "text/plain", // .txt
        "text/markdown", // .md
        "application/vnd.oasis.opendocument.text", // .odt
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "image/bmp",
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "audio/mpeg", // .mp3
        "video/mp4",
        "video/webm",
        "audio/wav",
        "audio/mp4", // .m4a
      };

      // Validate file type
      if(!allowedTypes.Contains(file.ContentType))
      {
        return BadRequest(new { error = $"File type not allowed: {file.ContentType}" });
      }

      // Validate file size (10 MB = 10 * 1024 * 1024 bytes)
      const long maxFileSize = 10 * 1024 * 1024; // 10 MB
      if(file.Length > maxFileSize)
      {
        var sizeMB = (file.Length / (1024.0 * 1024.0)).ToString("F2");
        return BadRequest(new { error = $"File size exceeds 10 MB limit ({sizeMB} MB)" });
      }

      var userId = GetUserId();
      var task = await _context.Tasks
        .FirstOrDefaultAsync(t => t.Id == id && t.AppUserId == userId);

      if(task == null)
        return NotFound(new { error = "Task not found" });

      try
      {
        string webRootPath = _env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
        var uploadDir = Path.Combine(webRootPath, "uploads");
        if(!Directory.Exists(uploadDir))
          Directory.CreateDirectory(uploadDir);

        var fileName = $"{Guid.NewGuid()}_{file.FileName}";
        var filePath = Path.Combine(uploadDir, fileName);

        using(var stream = new FileStream(filePath, FileMode.Create))
        {
          await file.CopyToAsync(stream);
        }

        task.FileUrl = $"/uploads/{fileName}";
        task.FileName = file.FileName;
        task.UpdatedAt = DateTime.UtcNow;

        _context.Tasks.Update(task);
        await _context.SaveChangesAsync();

        return Ok(new { fileUrl = task.FileUrl, fileName = task.FileName });
      }
      catch(Exception ex)
      {
        return StatusCode(500, new { error = "File upload failed", details = ex.Message });
      }
    }

    [HttpDelete("{id}/upload")]
    public async Task<IActionResult> DeleteFile(int id)
    {
      var userId = GetUserId();
      var task = await _context.Tasks
        .FirstOrDefaultAsync(t => t.Id == id && t.AppUserId == userId);

      if(task == null)
        return NotFound(new { error = "Task not found" });

      if(string.IsNullOrEmpty(task.FileUrl))
        return BadRequest(new { error = "No file attached to this task" });

      try
      {
        // Delete the file from disk
        var fileName = Path.GetFileName(task.FileUrl);
        var filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);
        
        if(System.IO.File.Exists(filePath))
          System.IO.File.Delete(filePath);

        // Clear file info from database
        task.FileUrl = null;
        task.FileName = null;
        task.UpdatedAt = DateTime.UtcNow;

        _context.Tasks.Update(task);
        await _context.SaveChangesAsync();

        return Ok(new { message = "File deleted successfully" });
      }
      catch(Exception ex)
      {
        return StatusCode(500, new { error = "File deletion failed", details = ex.Message });
      }
    }


    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteTask(int id)
    {
      var userId = GetUserId();
      var task = await _context.Tasks
        .FirstOrDefaultAsync(t => t.Id == id && t.AppUserId == userId);

      if(task == null)
        return NotFound(new { error = "Task not found" });

      try
      {
        // Delete file from disk if exists
        if(!string.IsNullOrEmpty(task.FileUrl))
        {
          var fileName = Path.GetFileName(task.FileUrl);
          var filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);
          
          if(System.IO.File.Exists(filePath))
            System.IO.File.Delete(filePath);
        }

        // Delete task from database
        _context.Tasks.Remove(task);
        await _context.SaveChangesAsync();

        return Ok(new { message = "Task deleted successfully" });
      }
      catch(Exception ex)
      {
        return StatusCode(500, new { error = "Task deletion failed", details = ex.Message });
      }
    }
  }
}
