namespace Turnos.data.entidades
{
    public class RefreshToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Token { get; set; } = string.Empty;
        public string JwtId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; } = false;
        public bool Revoked { get; set; } = false;
        public DateTime RevokedAt { get; set; } 
        public string? DeviceId { get; set; } 
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
    }
}
