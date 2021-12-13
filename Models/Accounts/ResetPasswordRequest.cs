using System.ComponentModel.DataAnnotations;

namespace stocks_backend.Models.Accounts
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set;}
        [Required]
        [MinLength(6)]
        public string Password { get; set;}
        [Required]
        [Compare("Password")]
        public string ConfirmPassword { get; set;}
    }
}