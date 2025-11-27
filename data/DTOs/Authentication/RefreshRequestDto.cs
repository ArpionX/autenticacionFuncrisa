namespace Turnos.data.DTOs.Authentication
{
    public class RefreshRequestDto
    {
        public string? RefreshToken { get; set; }

        public string? DeviceId { get; set; }
    }
}
