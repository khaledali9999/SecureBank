using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
namespace SecureBank;

public class AppUser : IdentityUser { public string FullName { get; set; } = ""; public string? LastIp { get; set; } }
public class Account { public int Id { get; set; } public string OwnerId { get; set; } = ""; public string Number { get; set; } = ""; public decimal Balance { get; set; } }
public class Transfer {
  public int Id { get; set; } public int FromAccountId { get; set; } public string ToAccountNumber { get; set; } = "";
  public decimal Amount { get; set; } public string Status { get; set; } = "Pending"; // Pending, PendingApproval, Completed, Rejected
  public string OwnerId { get; set; } = ""; public string? EmailCode { get; set; } public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
public class AuditLog { public int Id { get; set; } public string UserId { get; set; } = ""; public string Action { get; set; } = ""; public string Details { get; set; } = ""; public string Ip { get; set; } = ""; public DateTime At { get; set; } = DateTime.UtcNow; }
public class KycDoc { public int Id { get; set; } public string OwnerId { get; set; } = ""; public string StoredName { get; set; } = ""; public string OriginalName { get; set; } = ""; }

public class BankDb(DbContextOptions<BankDb> o) : IdentityDbContext<AppUser>(o) {
  public DbSet<Account> Accounts => Set<Account>(); public DbSet<Transfer> Transfers => Set<Transfer>();
  public DbSet<AuditLog> Audit => Set<AuditLog>(); public DbSet<KycDoc> Kyc => Set<KycDoc>();
}

// DTOs منفصلة = مفيش Mass Assignment
public record RegisterDto([Required, StringLength(100, MinimumLength = 3)] string FullName, [Required, EmailAddress] string Email, [Required] string Password);
public record LoginDto([Required, EmailAddress] string Email, [Required] string Password);
public record TransferDto([Required] int FromAccountId, [Required, StringLength(20)] string ToAccountNumber, [Range(0.01, 10_000_000)] decimal Amount);
public record ConfirmDto([Required] int TransferId, [Required] string TwoFactorCode, [Required] string EmailCode);
public record ChangePasswordDto([Required] string Current, [Required] string New);
