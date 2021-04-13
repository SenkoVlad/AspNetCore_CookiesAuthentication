using AspNet_AuthCookies.Infrastructure.Data;
using AspNet_AuthCookies.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using AspNet_AuthCookies.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AspNet_AuthCookies.Contollers
{
    public class AccountController : Controller
    {
        private UserContext db;
        public AccountController(UserContext context)
        {
            db = context;
        }
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel)
        {
            if(ModelState.IsValid)
            {
                User user = await db.Users
                                    .Include(u => u.Role)
                                    .FirstOrDefaultAsync(u => u.Email == loginViewModel.Email && u.Password == loginViewModel.Password);
                if(user != null)
                {
                    await Authenticate(user);
                    return RedirectToAction("Index", "Home");
                }
                ModelState.AddModelError("", "Некорректный логин или пароль");
            }
            return View(loginViewModel);
        }
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                User user = await db.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
                Role userRole = await db.Roles.FirstOrDefaultAsync(r => r.Name == "user");

                if (user == null)
                {
                    user = new User { Email = model.Email, Password = model.Password };

                    if (userRole != null)
                        user.Role = userRole;

                    // добавляем пользователя в бд
                    db.Users.Add(user);
                    await db.SaveChangesAsync();

                    await Authenticate(user); // аутентификация

                    return RedirectToAction("Index", "Home");
                }
                else
                    ModelState.AddModelError("", "Некорректные логин и(или) пароль");
            }
            return View(model);
        }

        private async Task Authenticate(User user)
        {
            // создаем один claim
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, user.Email),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, user.Role?.Name)
            };
            // создаем объект ClaimsIdentity
            ClaimsIdentity id = new ClaimsIdentity(claims, "ApplicationCookie", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            // установка аутентификационных куки
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Account");
        }

    }
}
