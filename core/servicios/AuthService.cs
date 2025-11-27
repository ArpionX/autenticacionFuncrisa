using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Turnos.core.interfaces;
using Turnos.data.DTOs.Authentication;
using Turnos.data.entidades;
using Turnos.data.repositorios.interfaces;

namespace Turnos.core.servicios
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppDbContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthService(IRefreshTokenRepository refreshTokenRepository, AppDbContext appDbContext , UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuracion)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _dbContext = appDbContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuracion;
            _signInManager = signInManager;
        }
        //Register
        public async Task<IdentityResult> RegisterAsync(IdentityUser usuario, string password, string role)
        {
            var roleExists = await _roleManager.RoleExistsAsync(role);
            if (!roleExists)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "RoleNotFound",
                    Description = $"El rol '{role}' no existe."
                });
            }

            var result = await _userManager.CreateAsync(usuario, password);
            if (!result.Succeeded) return result;

            await _userManager.AddToRoleAsync(usuario, role);

            return result;
        }
        //Login

        public async Task<AuthResponseDto?> LoginAsync(LoginDto request, string deviceId, string ip, string userAgent)
        {
            //buscar usuario por email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null) return null;

            //verificar password
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded) return null;

            //obtener roles del usuario
            var roles = await _userManager.GetRolesAsync(user);
            var jti = Guid.NewGuid().ToString();
            //si se verifico el email y password, generar el token
            var jwtResult = await GenerateJwtToken(user, roles, jti);

            //crear refresh token
            var refreshEntity = await SaveRefreshTokenAsync(user.Id,jti,deviceId,ip,userAgent);

            //Respuesta del login
            return new AuthResponseDto
            {
                Token = jwtResult.Token,
                Expiration = jwtResult.Expiration,
                UserName = user.UserName!,
                Email = user.Email!,
                Roles = roles.ToList(),
                RefreshToken = refreshEntity.Token
            };
        }
        private async Task<JwtResult> GenerateJwtToken(IdentityUser user, IList<string> roles, string jti)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //tiempo de expiracion desde config
            var expiration = DateTime.UtcNow.AddMinutes(jwtSettings.GetValue<double>("ExpireMinutes"));
            
            //creamos el claim
            var claims = new List<Claim> 
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName!),
                new Claim("uid", user.Id)
            };
            //agregar roles al claim
            foreach(var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            //se crea el token
            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: creds
            );

            return new JwtResult
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration
            };
        }

        private string CreateRefreshToken(int size = 64)
        {
            var random = new byte[size];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            return Convert.ToBase64String(random);
        }

        // Método que orquesta la creación y guardado
        private async Task<RefreshToken> SaveRefreshTokenAsync(string userId,string jti,string deviceId,string ip,string userAgent)
        {
            var token = CreateRefreshToken(); // Genera el token

            var refreshEntity = new RefreshToken
            {
                Token = token,
                JwtId = jti,
                UserId = userId, 
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                DeviceId = deviceId,
                IpAddress = ip,
                UserAgent = userAgent
            };


            await _refreshTokenRepository.addAsync(refreshEntity);

            return refreshEntity;
        }
        public async Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken, string expiredJwt)
        {
            // 1. Extraer JTI del JWT expirado
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(expiredJwt);
            var jtiFromJwt = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

            if (string.IsNullOrEmpty(jtiFromJwt))
                return null;

            // 2. Buscar el RefreshToken en BD usando el JTI
            var storedRefreshToken = await _refreshTokenRepository.GetByTokenAndJtiAsync(refreshToken, jtiFromJwt);

            if (storedRefreshToken == null)
                return null; // RefreshToken inválido o no coincide con el JWT

            // 3. Revocar el RefreshToken viejo
            storedRefreshToken.Revoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;

            // 4. Generar nuevo JWT y nuevo RefreshToken con NUEVO JTI
            var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
            var roles = await _userManager.GetRolesAsync(user);

            var newJti = Guid.NewGuid().ToString();
            var newJwt = await GenerateJwtToken(user, roles, newJti);

            var newRefreshEntity = await SaveRefreshTokenAsync(
                user.Id,
                newJti,  // ← NUEVO JTI para el nuevo par JWT/RefreshToken
                storedRefreshToken.DeviceId!,
                storedRefreshToken.IpAddress!,
                storedRefreshToken.UserAgent!
            );

            await _dbContext.SaveChangesAsync();

            return new AuthResponseDto
            {
                Token = newJwt.Token,
                Expiration = newJwt.Expiration,
                UserName = user.UserName!,
                Email = user.Email!,
                Roles = roles.ToList(),
                RefreshToken = newRefreshEntity.Token
            };
        }
    }
}
