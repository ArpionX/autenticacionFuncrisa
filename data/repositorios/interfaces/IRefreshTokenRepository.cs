using Turnos.data.entidades;

namespace Turnos.data.repositorios.interfaces
{
    public interface IRefreshTokenRepository
    {
        Task addAsync(RefreshToken token);
        Task<RefreshToken?> GetByTokenAndJtiAsync(string refreshToken, string jti);
    }
}
