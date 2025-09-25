using System.Net;
using System.Net.Http.Json;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

public partial class Program
{
    // Resposta do hCaptcha
    public record HcaptchaVerifyResponse(
        bool success,
        DateTimeOffset? challenge_ts,
        string hostname,
        string[]? error_codes,
        string? credit
    );

    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // --- Configs ---
        var hcaptchaSecret = builder.Configuration["HCAPTCHA_SECRET"];
        var jwtKey = builder.Configuration["JWT_KEY"];
        if (string.IsNullOrWhiteSpace(hcaptchaSecret))
            Console.WriteLine("ATENÇÃO: defina HCAPTCHA_SECRET.");
        if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
            Console.WriteLine("ATENÇÃO: defina JWT_KEY (>=32 chars).");

        // --- HttpClient (hCaptcha) ---
        builder.Services.AddHttpClient("hcaptcha", c =>
        {
            c.BaseAddress = new Uri("https://hcaptcha.com/");
            c.Timeout = TimeSpan.FromSeconds(8);
        });

        // --- AuthN/AuthZ (JWT Bearer) ---
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey ?? "dev_key_somente_para_demo_mude_isto_agora_mesmo_1234567890"));
        builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };
            });
        builder.Services.AddAuthorization();

        // --- CORS (libere somente o que precisa em prod) ---
        builder.Services.AddCors(opt =>
        {
            opt.AddDefaultPolicy(policy =>
                policy
                    .WithOrigins("http://localhost:5113", "http://localhost:5000") // ajuste
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials());
        });

        // --- Rate Limiting básico (evita brute force) ---
        builder.Services.AddRateLimiter(opt =>
        {
            opt.AddFixedWindowLimiter("login", o =>
            {
                o.PermitLimit = 10;                  // 10tentativas
                o.Window = TimeSpan.FromMinutes(1);  // por minuto
                o.QueueLimit = 0;
            });
        });

        var app = builder.Build();

        app.UseDefaultFiles();
        app.UseStaticFiles();

        app.UseCors();
        app.UseRateLimiter();

        app.UseAuthentication();
        app.UseAuthorization();

        // GET /health
        app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

        // POST /api/login (valida hCaptcha -> confere credenciais -> gera JWT)
        app.MapPost("/api/login", async (HttpRequest request, IHttpClientFactory httpClientFactory) =>
        {
            var form = await request.ReadFormAsync();
            var email = form["email"].ToString();
            var password = form["password"].ToString();
            var token = form["hCaptchaToken"].ToString();

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                return Results.Json(new { ok = false, error = "E-mail e senha são obrigatórios." });

            if (string.IsNullOrWhiteSpace(token))
                return Results.Json(new { ok = false, error = "Token do hCaptcha ausente." });

            // 1) Verifica hCaptcha
            var client = httpClientFactory.CreateClient("hcaptcha");
            using var verifyForm = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string,string>("secret", app.Configuration["HCAPTCHA_SECRET"] ?? ""),
                new KeyValuePair<string,string>("response", token),
                new KeyValuePair<string,string>("remoteip", request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "")
            });

            HttpResponseMessage resp;
            try
            {
                resp = await client.PostAsync("siteverify", verifyForm);
            }
            catch (TaskCanceledException)
            {
                return Results.Json(new { ok = false, error = "Timeout ao verificar hCaptcha." });
            }

            if (resp.StatusCode != HttpStatusCode.OK)
                return Results.Json(new { ok = false, error = "Falha ao verificar hCaptcha." });

            var verify = await resp.Content.ReadFromJsonAsync<HcaptchaVerifyResponse>();
            if (verify is null || !verify.success)
            {
                var codes = verify?.error_codes is { Length: > 0 } ? string.Join(", ", verify!.error_codes!) : "desconhecido";
                return Results.Json(new { ok = false, error = $"hCaptcha inválido ({codes})." });
            }

            // (Opcional) Confere hostname esperado (se seu site roda em domínio fixo)
            // var expectedHost = "seu-dominio.com"; 
            // if (!string.Equals(verify.hostname, expectedHost, StringComparison.OrdinalIgnoreCase))
            //     return Results.Json(new { ok = false, error = "hCaptcha hostname não confere." });

            // 2) Autenticação (DEMO – troque por sua base/DB com senha hash!)
            const string demoEmail = "bastoslucas55@gmail.com";
            const string demoPass  = "admin123@"; // NÃO use isso em produção
            if (!email.Equals(demoEmail, StringComparison.OrdinalIgnoreCase) || password != demoPass)
                return Results.Json(new { ok = false, error = "Credenciais inválidas." });

            // 3) Gera JWT
            var jwt = CreateJwt(email, key);

            return Results.Json(new { ok = true, token = jwt, user = new { email } });
        })
        .RequireRateLimiting("login");

        // GET /api/profile (protegida)
        app.MapGet("/api/profile", (ClaimsPrincipal user) =>
        {
            var email = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.Identity?.Name ?? "desconhecido";
            return Results.Ok(new
            {
                email,
                roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray(),
                issuedAt = DateTimeOffset.UtcNow
            });
        }).RequireAuthorization();

        await app.RunAsync();

        // ===== Local function =====
        static string CreateJwt(string email, SymmetricSecurityKey key)
        {
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, email),
                new Claim(ClaimTypes.Name, email),
                new Claim(ClaimTypes.Role, "user")
            };
            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddHours(2),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
