namespace Turnos.data.DTOs.Authentication
{
    public class JwtResult
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
    }
}
