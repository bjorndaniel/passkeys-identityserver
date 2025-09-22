using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Client.Controllers;

public class AccountController : Controller
{
    [HttpGet("/login")]
    public new IActionResult Challenge()
    {
        return base.Challenge(new AuthenticationProperties
        {
            RedirectUri = "/"
        }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("/logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        // Sign out of the local cookie authentication scheme
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Sign out of the OpenID Connect authentication scheme
        return base.SignOut(new AuthenticationProperties
        {
            RedirectUri = "/"
        }, OpenIdConnectDefaults.AuthenticationScheme);
    }
}
