using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using Microsoft.Extensions.Logging;
using stocks_backend.Models.Accounts;
using stocks_backend.Services;

namespace stocks_backend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountsController : BaseController
    {
        private readonly ILogger<AccountsController> _logger;
        private readonly IAccountService _accountService;
        private readonly IMapper _mapper;

        public AccountsController(ILogger<AccountsController> logger, IAccountService accountService)
        {
            _accountService = accountService;
            _logger = logger;
        }
        // [HttpPost]
        // public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
        // {
        //     return null;
        // }

        [HttpPost("register")]
        public IActionResult Register(RegisterRequest model)
        {
            _accountService.Register(model, Request.Headers["origin"]);
            return Ok(new { message = "Registration successful, please check your email for verification instructions" });
        }
    }
}
