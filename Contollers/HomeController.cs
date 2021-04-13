using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNet_AuthCookies.Contollers
{
    [Authorize]
    public class HomeController : Controller
    {
        [AllowAnonymous]
        public IActionResult Index()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
                return View("Index" ,User.Identity.Name);
            else
                return View("Index", "not authorized");
        }

        public IActionResult About()
        {
            return Content("About", "Authorized");
        }
    }
}
