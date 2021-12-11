using stocks_backend.Heplers;
using stocks_backend.Models.Accounts;
using AutoMapper;
using BC = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Linq;
using System;
using System.Security.Cryptography;
using stocks_backend.Entities;

namespace stocks_backend.Services
{
    public interface IAccountService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        void Register(RegisterRequest model, string origin);
    }

    public class AccountService : IAccountService
    {
        private readonly DataContext _context;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;

        public AccountService(
            DataContext context,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            IEmailService emailService)
        {
            _context = context;
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _emailService = emailService;
        }
        public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            throw new System.NotImplementedException();
        }

        public void Register(RegisterRequest model, string origin)
        {
            // validate
            if(_context.Accounts.Any(x => x.Email == model.Email))
            {
                // send alread registered error in email to prevent account enumeration
                sendAlreadyRegisteredEmail(model.Email, origin);
                return;
            }

            // map models to new account object
            var account = _mapper.Map<Account>(model);

            // first registered account ia an admin
            var isFirstAccount = _context.Accounts.Count() == 0;
            account.Role  = isFirstAccount? Role.Admin : Role.User;
            account.Created = DateTime.UtcNow;
            account.VerificationToken = randomTokenString();

            // hash password
            account.PasswordHash = BC.HashPassword(model.Password);

            // save account
            _context.Accounts.Add(account);
            _context.SaveChanges();

            // send email
            sendVerificationEmail(account, origin);
        }

        private void sendVerificationEmail(Account account, string origin)
        {
           string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/account/verify-email?token={account.VerificationToken}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                             <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                             <p><code>{account.VerificationToken}</code></p>";
            }

            _emailService.Send(
                to: account.Email,
                subject: "Sign-up Verification API - Verify Email",
                html: $@"<h4>Verify Email</h4>
                         <p>Thanks for registering!</p>
                         {message}"
            );
        }

        private string randomTokenString()
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            // convert random bytes to hex string
            return BitConverter.ToString(randomBytes).Replace("-","");
        }

        private void sendAlreadyRegisteredEmail(string email, string origin)
        {
            string message;
            if(!string.IsNullOrEmpty(origin))
                message = $@"<p>If you don't know your password please visit the <a href=""{origin}/account/forgot-password"">forgot password</a> page.</p>";
            else
                message = "<p>If you don't know your password you can reset it via the <code>/accounts/forgot-password</code> api route.</p>";

            _emailService.Send(
                to: email,
                subject: "Sign-up Verification API - Email Already Registered",
                html: $@"<h4>Email Already Registered</h4>
                         <p>Your email <strong>{email}</strong> is already registered.</p>
                         {message}"
            );
        }
    }
}














