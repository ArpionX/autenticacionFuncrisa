using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Turnos.core.interfaces;
using Turnos.core.servicios;
using Turnos.data.DTOs.Authentication;
using Turnos.data.entidades;

namespace Turnos.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<IdentityRole> _roleManager;
        public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration, 
            IAuthService authService, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _authService = authService;
            _configuration = configuration;
            _roleManager = roleManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new IdentityUser
            {
                UserName = request.UserName,
                Email = request.Email
            };

            var result = await _authService.RegisterAsync(user, request.Password,request.Role);

            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok("Usuario registrado correctamente");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            //obtener la informacion para el loginAsync
            var deviceId = Request.Headers["X-Device-Id"].FirstOrDefault() ?? "unknown-device";
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";
            var userAgent = Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown-user-agent";
            
            //Servicio Login Async
            var result = await _authService.LoginAsync(loginDto, deviceId, ip, userAgent);
            if (result == null)//si no se autentico credenciales invalidas
                return Unauthorized("Credenciales invalidas");

            //Setear un cookie
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),       
                Path = "/"
            };
            Response.Cookies.Append("___RefreshToken", result.RefreshToken, cookieOptions);

            result.RefreshToken = string.Empty; // No enviar el refresh token en el cuerpo de la respuesta para mayor seguridad

            return Ok(result);
        }

        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return BadRequest("El nombre del rol no puede estar vacío");
            if (await _roleManager.RoleExistsAsync(roleName))
                return BadRequest("El rol ya existe");

            await _roleManager.CreateAsync(new IdentityRole(roleName));
            return Ok($"Rol '{roleName}' creado correctamente");
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody]RefreshRequestDto Dto)
        {
            var refreshToken = Dto.RefreshToken ?? Request.Cookies["___RefreshToken"];
            if (string.IsNullOrEmpty(refreshToken)) return BadRequest("Refresh token no proporcionado");

            var expiredJwt = Request.Headers["Authorization"].FirstOrDefault()?.Split("").Last();
            if (string.IsNullOrEmpty(expiredJwt)) return BadRequest("JWT expirado");

            var result = await _authService.RefreshTokenAsync(refreshToken, expiredJwt);
            if (result == null) return Unauthorized("No se pudo refrescar el token");

            if (Dto.RefreshToken == null) // Si el token original vino de la cookie, renovamos la cookie.
            {
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddDays(7), // **NOTA:** Considera usar la expiración del nuevo token. Aquí se mantiene la duración de 7 días como en Login.
                    Path = "/"
                };
                Response.Cookies.Append("___RefreshToken", result.RefreshToken, cookieOptions);
            }

            // 5. Limpiar el RefreshToken del cuerpo para no enviarlo en la respuesta.
            result.RefreshToken = string.Empty;

            return Ok(result);
        }

    }
}
