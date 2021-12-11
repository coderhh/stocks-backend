using System.ComponentModel.DataAnnotations;

namespace stocks_backend.Models.Accounts
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set;}
    }
}