using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
namespace SecureBank;

public abstract class BaseCtl : ControllerBase { protected string Uid => User.FindFirstValue(ClaimTypes.NameIdentifier)!; }

[Route("Account")]
public class AccountController(UserManager<AppUser> um, SignInManager<AppUser> sm, AuditService audit) : BaseCtl {
  [HttpPost("Register")]
  public async Task<IActionResult> Register(RegisterDto d) {
    var u = new AppUser { UserName = d.Email, Email = d.Email, FullName = d.FullName };
    var r = await um.CreateAsync(u, d.Password);
    if (!r.Succeeded) return BadRequest(r.Errors.Select(e => e.Description));
    await um.AddToRoleAsync(u, "Customer"); // الدور بيتحدد في السيرفر مش من الـ Input
    await audit.Log(u.Id, "REGISTER", d.Email);
    return Ok();
  }

  [HttpPost("Login"), EnableRateLimiting("login")]
  public async Task<IActionResult> Login(LoginDto d) {
    HttpContext.Session?.Clear();
    var res = await sm.PasswordSignInAsync(d.Email, d.Password, false, lockoutOnFailure: true); // Cookie جديد = Anti-Fixation
    var u = await um.FindByEmailAsync(d.Email);
    if (u != null) {
      var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
      if (res.Succeeded && u.LastIp != null && u.LastIp != ip) audit.Alert($"New IP for {u.Id}: {ip}");
      if (res.Succeeded) { u.LastIp = ip; await um.UpdateAsync(u); }
      await audit.Log(u.Id, res.Succeeded ? "LOGIN_OK" : res.IsLockedOut ? "LOGIN_LOCKED" : "LOGIN_FAIL", "");
    }
    return res.Succeeded ? Ok() : Unauthorized("Invalid credentials"); // رسالة موحدة
  }

  [Authorize, HttpPost("ChangePassword")]
  public async Task<IActionResult> ChangePassword(ChangePasswordDto d) {
    var u = (await um.GetUserAsync(User))!;
    var r = await um.ChangePasswordAsync(u, d.Current, d.New); // بيجدد SecurityStamp
    if (!r.Succeeded) return BadRequest(r.Errors.Select(e => e.Description));
    await um.UpdateSecurityStampAsync(u); // يلغي كل الـ Sessions في الأجهزة التانية
    await sm.RefreshSignInAsync(u);
    await audit.Log(u.Id, "PASSWORD_CHANGED", "all sessions invalidated");
    return Ok();
  }

  [Authorize, HttpPost("Enable2FA")]
  public async Task<IActionResult> Enable2FA() {
    var u = (await um.GetUserAsync(User))!;
    await um.ResetAuthenticatorKeyAsync(u);
    var key = await um.GetAuthenticatorKeyAsync(u);
    await um.SetTwoFactorEnabledAsync(u, true);
    return Ok(new { key }); // اعرضه كـ QR لـ Authenticator App
  }
}

[Route("Transfers"), Authorize]
public class TransfersController(TransferService svc) : BaseCtl {
  [HttpPost, Authorize(Policy = "CanTransfer"), EnableRateLimiting("transfer")]
  public async Task<IActionResult> Start(TransferDto d) { var (ok, m, id) = await svc.Start(Uid, d); return ok ? Ok(new { m, id }) : BadRequest(m); }

  [HttpPost("Confirm"), Authorize(Policy = "CanTransfer"), EnableRateLimiting("transfer")]
  public async Task<IActionResult> Confirm(ConfirmDto d) { var (ok, m) = await svc.Confirm(Uid, d); return ok ? Ok(m) : BadRequest(m); }

  [HttpPost("Approve/{id:int}"), Authorize(Policy = "CanApproveLoans")]
  public async Task<IActionResult> Approve(int id) { var (ok, m) = await svc.Approve(Uid, id); return ok ? Ok(m) : NotFound(m); }
}

[Route("Statements"), Authorize]
public class StatementsController(BankDb db, AuditService audit) : BaseCtl {
  [HttpGet("{accountId:int}")]
  public async Task<IActionResult> Get(int accountId) {
    var acc = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId && a.OwnerId == Uid); // IDOR
    if (acc == null) { await audit.Log(Uid, "DENIED_STATEMENT", $"acc {accountId}"); return NotFound(); }
    var tx = await db.Transfers.AsNoTracking().Where(t => t.FromAccountId == acc.Id)
      .Select(t => new { t.Id, t.Amount, t.Status, t.CreatedAt }).ToListAsync(); // Projection = مفيش حقول زيادة
    return Ok(new { Account = "****" + acc.Number[^4..], acc.Balance, Transactions = tx }); // آخر 4 أرقام بس
  }
}

[Route("Kyc"), Authorize]
public class KycController(KycService svc) : BaseCtl {
  [HttpPost, RequestSizeLimit(10 * 1024 * 1024)]
  public async Task<IActionResult> Upload(IFormFile file) { var (ok, m) = await svc.Save(Uid, file); return ok ? Ok(m) : BadRequest(m); }
}
