using System.ComponentModel.DataAnnotations;

namespace Turnos.data.DTOs.Authentication
{
    public class RegisterDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
        [Required]
        [MinLength(5)]
        public string UserName { get; set; } = null!;
        [Required]
        public string Role { get; set; } = null!;

    }
}
