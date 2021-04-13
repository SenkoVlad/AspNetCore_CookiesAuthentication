using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AspNet_AuthCookies.Contollers
{
    public class HomeController : Controller
    {
        [Authorize(Roles = "admin, user")]
        public IActionResult Index()
        {
            string role = User.FindFirst(claim => claim.Type == ClaimsIdentity.DefaultRoleClaimType).Value;
            return View("Index" ,$"User: {User.Identity.Name}. Role: {role}");
        }

        [Authorize(Roles = "admin")]
        public IActionResult About()
        {
            return Content("About", "Authorized");
        }
    }
}
