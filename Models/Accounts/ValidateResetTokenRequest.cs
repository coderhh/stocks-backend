using System.ComponentModel.DataAnnotations;

namespace stocks_backend.Models.Accounts
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token {get; set;}
    }
}