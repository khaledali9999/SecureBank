using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
namespace SecureBank;

// BCrypt Work Factor 12
public class BcryptHasher : IPasswordHasher<AppUser> {
  public string HashPassword(AppUser u, string p) => BCrypt.Net.BCrypt.HashPassword(p, 12);
  public PasswordVerificationResult VerifyHashedPassword(AppUser u, string h, string p) =>
    BCrypt.Net.BCrypt.Verify(p, h) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
}

public class AuditService(BankDb db, IHttpContextAccessor http, ILogger<AuditService> log, IConfiguration cfg) {
  static readonly Regex Acc = new(@"\b\d{8,19}\b"), Cvv = new(@"(?i)cvv\W*\d{3,4}");
  public static string Mask(string s) => Cvv.Replace(Acc.Replace(s, m => new string('*', m.Value.Length - 4) + m.Value[^4..]), "CVV:***");
  public async Task Log(string userId, string action, string details) {
    var ip = http.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "?";
    var safe = Mask(details);
    db.Audit.Add(new AuditLog { UserId = userId, Action = action, Details = safe, Ip = ip });
    await db.SaveChangesAsync();
    log.LogInformation("AUDIT {User} {Action} {Details} {Ip}", userId, action, safe, ip);
    if (action.StartsWith("DENIED")) { // تصعيد بعد 3 محاولات فاشلة
      var since = DateTime.UtcNow.AddMinutes(-30);
      if (await db.Audit.CountAsync(a => a.UserId == userId && a.Action.StartsWith("DENIED") && a.At > since) >= 3)
        Alert($"ESCALATION: {userId} has 3+ denied access attempts");
    }
  }
  public void Alert(string msg) => log.LogCritical("ADMIN ALERT: {Msg}", msg); // وصّلها بإيميل/SignalR
}

public class TransferService(BankDb db, AuditService audit, UserManager<AppUser> um) {
  const decimal ApprovalLimit = 50_000m;

  public async Task<(bool ok, string msg, int id)> Start(string userId, TransferDto d) {
    // IDOR: الحساب لازم يكون بتاع المستخدم
    var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == d.FromAccountId && a.OwnerId == userId);
    if (acc == null) { await audit.Log(userId, "DENIED_ACCOUNT", $"acc {d.FromAccountId}"); return (false, "Not found", 0); }
    if (d.Amount > acc.Balance) return (false, "Insufficient funds", 0);
    var user = (await um.FindByIdAsync(userId))!;
    if (!user.TwoFactorEnabled) return (false, "Enable 2FA first", 0);
    var t = new Transfer { FromAccountId = acc.Id, ToAccountNumber = d.ToAccountNumber, Amount = d.Amount, OwnerId = userId,
      EmailCode = Random.Shared.Next(100000, 999999).ToString() }; // اتبعت بالإيميل (IEmailSender)
    db.Transfers.Add(t); await db.SaveChangesAsync();
    await audit.Log(userId, "TRANSFER_STARTED", $"{d.Amount} to {d.ToAccountNumber}");
    if (d.Amount > 25_000m) audit.Alert($"Large transfer {d.Amount} by {userId}");
    return (true, "Confirm with 2FA + email code", t.Id);
  }

  public async Task<(bool ok, string msg)> Confirm(string userId, ConfirmDto d) {
    var t = await db.Transfers.FirstOrDefaultAsync(x => x.Id == d.TransferId && x.OwnerId == userId && x.Status == "Pending");
    if (t == null) { await audit.Log(userId, "DENIED_TRANSFER", $"id {d.TransferId}"); return (false, "Not found"); }
    var user = (await um.FindByIdAsync(userId))!;
    var ok2fa = await um.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, d.TwoFactorCode);
    if (!ok2fa || t.EmailCode != d.EmailCode) { await audit.Log(userId, "TRANSFER_BAD_CODE", $"id {t.Id}"); return (false, "Invalid codes"); }
    if (t.Amount > ApprovalLimit) { t.Status = "PendingApproval"; await db.SaveChangesAsync(); await audit.Log(userId, "TRANSFER_NEEDS_APPROVAL", $"id {t.Id}"); return (true, "Awaiting manager approval"); }
    return await Execute(t, userId);
  }

  public async Task<(bool ok, string msg)> Approve(string managerId, int id) {
    var t = await db.Transfers.FirstOrDefaultAsync(x => x.Id == id && x.Status == "PendingApproval");
    if (t == null) return (false, "Not found");
    await audit.Log(managerId, "TRANSFER_APPROVED", $"id {id}");
    return await Execute(t, managerId);
  }

  async Task<(bool, string)> Execute(Transfer t, string actor) {
    await using var tx = await db.Database.BeginTransactionAsync();
    var from = await db.Accounts.FirstAsync(a => a.Id == t.FromAccountId);
    if (from.Balance < t.Amount) return (false, "Insufficient funds");
    from.Balance -= t.Amount;
    var to = await db.Accounts.FirstOrDefaultAsync(a => a.Number == t.ToAccountNumber);
    if (to != null) to.Balance += t.Amount;
    t.Status = "Completed"; await db.SaveChangesAsync(); await tx.CommitAsync();
    await audit.Log(actor, "TRANSFER_COMPLETED", $"id {t.Id} amount {t.Amount}");
    return (true, "Done");
  }
}

public class KycService(BankDb db, AuditService audit, IConfiguration cfg) {
  const long Max = 10 * 1024 * 1024;
  static readonly Dictionary<string, byte[][]> Magic = new() {
    [".jpg"] = [[0xFF, 0xD8, 0xFF]], [".png"] = [[0x89, 0x50, 0x4E, 0x47]], [".pdf"] = [[0x25, 0x50, 0x44, 0x46]] };

  public async Task<(bool, string)> Save(string userId, IFormFile f) {
    if (f.Length == 0 || f.Length > Max) return (false, "Invalid size (max 10MB)");
    var ext = Path.GetExtension(f.FileName).ToLowerInvariant();
    if (!Magic.TryGetValue(ext, out var sigs)) return (false, "Type not allowed");
    var head = new byte[4];
    await using (var s = f.OpenReadStream()) await s.ReadExactlyAsync(head, 0, 4);
    if (!sigs.Any(sig => head.Take(sig.Length).SequenceEqual(sig))) return (false, "Content doesn't match extension");
    var name = $"{Guid.NewGuid()}{ext}"; // GUID بدل الاسم الأصلي (بيمنع Path Traversal)
    var dir = cfg["Storage:Kyc"] ?? Path.Combine(Path.GetTempPath(), "securebank-kyc"); // برا الـ wwwroot
    Directory.CreateDirectory(dir);
    await using (var o = File.Create(Path.Combine(dir, name))) await f.CopyToAsync(o);
    db.Kyc.Add(new KycDoc { OwnerId = userId, StoredName = name, OriginalName = Path.GetFileName(f.FileName) });
    await db.SaveChangesAsync(); await audit.Log(userId, "KYC_UPLOAD", name);
    return (true, name);
  }
}
