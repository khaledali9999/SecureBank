# Secure Banking Portal

## تشغيل
`dotnet restore && dotnet run` (محتاج .NET 8 و HTTPS dev cert: `dotnet dev-certs https --trust`)

## Security README (الطبقات)
| الطبقة | التنفيذ | الملف |
|---|---|---|
| Password Policy | 12 حرف + رقم + رمز + Upper/Lower | Program.cs |
| Hashing | BCrypt Work Factor 12 | Services.cs `BcryptHasher` |
| Lockout | 5 محاولات فاشلة → 15 دقيقة | Program.cs |
| 2FA | Authenticator TOTP + كود إيميل لكل تحويل | TransferService.Confirm |
| Roles / Policies | Customer, Teller, Manager, Admin / CanTransfer, CanViewAllAccounts, CanApproveLoans | Program.cs |
| Session | 10 دقايق + Sliding + HttpOnly + Secure + SameSite=Strict | Program.cs |
| Logout all devices | SecurityStamp + ValidationInterval=0 | AccountController.ChangePassword |
| Anti-Fixation | Cookie جديد عند كل Login + Session.Clear | AccountController.Login |
| SQLi | EF Core (Parameterized) | كل الاستعلامات |
| XSS | Output Encoding + CSP + JSON API | Middleware.cs |
| CSRF | AutoValidateAntiforgeryToken على كل POST + SameSite=Strict | Program.cs |
| IDOR | كل Query فيها `OwnerId == Uid` + Log للمحاولات الفاشلة | Services/Controllers |
| Mass Assignment | DTOs (records) + الدور يتحدد في السيرفر | Domain.cs |
| File Upload | Magic Numbers + 10MB + GUID + خارج wwwroot | KycService |
| Headers | CSP, HSTS, XFO, nosniff, Referrer, Permissions | Middleware.cs |
| Rate Limit | Login 5/15د لكل IP، Transfer 100/ساعة لكل مستخدم | Program.cs |
| Audit + Masking | مين/إمتى/IP/إيه، وإخفاء الأرقام و CVV | AuditService |
| Alerts | IP جديد، مبلغ كبير، 3 محاولات DENIED → تصعيد | AuditService.Alert |
| Business Rules | >50,000 موافقة Manager، آخر 4 أرقام بس في الكشف | TransferService, StatementsController |

## Threat Model (STRIDE مختصر)
| التهديد | السيناريو | التخفيف |
|---|---|---|
| Spoofing | سرقة/تخمين باسورد | BCrypt، Lockout، Rate Limit، 2FA |
| Tampering | تعديل المبلغ/الحساب، Mass Assignment | DTOs، Validation سيرفر، Transaction |
| Repudiation | إنكار عملية | Audit Log لكل عملية |
| Info Disclosure | IDOR، تسريب Logs، رفع Shell | Ownership checks، Masking، Magic Numbers |
| DoS | Brute force / Flood | Rate Limiting، حد حجم الرفع |
| Elevation | عميل يعمل Approve | Policies + Role Checks |
| Session Hijack | سرقة Cookie | HttpOnly/Secure/Strict، Timeout 10د |
| CSRF/XSS | تحويل من موقع خبيث | Anti-Forgery، CSP، SameSite |

## ملاحظات
- إرسال الإيميل و PDF Export و Alert للأدمن (SignalR) متوصلين كنقاط تمدد (`AuditService.Alert`, `EmailCode`).
- لازم تضيف Migrations و Unit Tests و فيديو الشرح قبل التسليم.
