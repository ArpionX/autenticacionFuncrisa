using Microsoft.EntityFrameworkCore;
using Turnos.data.entidades;
using Turnos.data.repositorios.interfaces;

namespace Turnos.data.repositorios.repositories
{
    public class RefreshTokenRepository: IRefreshTokenRepository
    {
        private readonly AppDbContext _context;
        public RefreshTokenRepository(AppDbContext context)
        {
            _context = context;
        }
        public async Task addAsync(RefreshToken token)
        {
            _context.refreshTokens.Add(token);
            await _context.SaveChangesAsync();
        }
        public async Task<RefreshToken?> GetByTokenAndJtiAsync(string refreshToken, string jti)
        {
            var result = await _context.refreshTokens.FirstOrDefaultAsync(
                t => t.Token == refreshToken &&
                t.JwtId == jti &&
                t.ExpiresAt > DateTime.UtcNow &&
                !t.Revoked);
            return result;
        }
    }
}
