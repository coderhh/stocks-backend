using System.ComponentModel.DataAnnotations;

namespace stocks_backend.Models.Accounts
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set;}
    }
}