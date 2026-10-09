namespace SecureBank;
public class SecurityHeadersMiddleware(RequestDelegate next) {
  public Task InvokeAsync(HttpContext c) {
    var h = c.Response.Headers;
    h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; object-src 'none'";
    h["X-Frame-Options"] = "DENY";
    h["X-Content-Type-Options"] = "nosniff";
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    h["Referrer-Policy"] = "no-referrer";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h["Cache-Control"] = "no-store";
    return next(c);
  }
}
