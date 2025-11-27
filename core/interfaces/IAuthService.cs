using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using Turnos.data.DTOs.Authentication;
using Turnos.data.entidades;

namespace Turnos.core.interfaces
{
    public interface IAuthService
    {
        Task<AuthResponseDto> LoginAsync(LoginDto request, string deviceId, string ip, string userAgent);
        Task<IdentityResult> RegisterAsync(IdentityUser usuario, string password, string role);
        Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken, string expiredJwt);
    }
}
