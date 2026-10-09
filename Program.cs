using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureBank;

var b = WebApplication.CreateBuilder(args);
b.Services.AddDbContext<BankDb>(o => o.UseSqlite("Data Source=bank.db")); // EF = Parameterized Queries
b.Services.AddHttpContextAccessor();

b.Services.AddIdentity<AppUser, IdentityRole>(o => {
  o.Password.RequiredLength = 12; o.Password.RequireDigit = true; o.Password.RequireNonAlphanumeric = true;
  o.Password.RequireUppercase = true; o.Password.RequireLowercase = true;
  o.Lockout.MaxFailedAccessAttempts = 5; o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
  o.User.RequireUniqueEmail = true;
}).AddEntityFrameworkStores<BankDb>().AddDefaultTokenProviders();
b.Services.AddScoped<IPasswordHasher<AppUser>, BcryptHasher>();

b.Services.ConfigureApplicationCookie(o => {
  o.Cookie.HttpOnly = true; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Strict;
  o.ExpireTimeSpan = TimeSpan.FromMinutes(10); o.SlidingExpiration = true;
  o.LoginPath = "/Account/Login"; o.AccessDeniedPath = "/Account/Denied";
});
// بيتحقق من الـ SecurityStamp في كل Request => تغيير الباسورد = Logout من كل الأجهزة
b.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero);

b.Services.AddAuthorization(o => {
  o.AddPolicy("CanTransfer", p => p.RequireRole("Customer").RequireAuthenticatedUser());
  o.AddPolicy("CanViewAllAccounts", p => p.RequireRole("Teller", "Manager", "Admin"));
  o.AddPolicy("CanApproveLoans", p => p.RequireRole("Manager", "Admin"));
});

b.Services.AddRateLimiter(o => {
  o.RejectionStatusCode = 429;
  o.AddPolicy("login", c => RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString() ?? "x",
    _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) }));
  o.AddPolicy("transfer", c => RateLimitPartition.GetFixedWindowLimiter(c.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anon",
    _ => new FixedWindowRateLimiterOptions { PermitLimit = 100, Window = TimeSpan.FromHours(1) }));
});

b.Services.AddAntiforgery(o => { o.Cookie.HttpOnly = true; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Strict; });
b.Services.AddControllers(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())); // CSRF على كل POST
b.Services.AddScoped<AuditService>(); b.Services.AddScoped<TransferService>(); b.Services.AddScoped<KycService>();

var app = b.Build();
app.UseHttpsRedirection(); app.UseHsts();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization();
app.MapControllers();
using (var s = app.Services.CreateScope()) {
  s.ServiceProvider.GetRequiredService<BankDb>().Database.EnsureCreated();
  var rm = s.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
  foreach (var r in new[] { "Customer", "Teller", "Manager", "Admin" }) if (!await rm.RoleExistsAsync(r)) await rm.CreateAsync(new(r));
}
app.Run();
