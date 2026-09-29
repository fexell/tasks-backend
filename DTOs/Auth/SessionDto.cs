using System;

namespace Entry.Auth.DTOs
{
  public record SessionDto(
    Guid Id,
    string Device,
    DateTime LastActiveAt,
    bool IsCurrent
  );
}