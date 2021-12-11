using Microsoft.AspNetCore.Mvc;
using stocks_backend.Entities;

namespace stocks_backend.Controllers
{
    [Controller]
    public abstract class BaseController: ControllerBase
    {
        public Account Account => (Account) HttpContext.Items["Account"];
    }

}