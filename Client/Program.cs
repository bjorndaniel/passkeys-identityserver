using Client.Components;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add authentication and authorization
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "oidc";
})
.AddCookie()
.AddOpenIdConnect("oidc", options =>
{
    options.Authority = "https://localhost:5001";
    options.ClientId = "interactive";
    options.ClientSecret = "49C1A7E1-0C79-4A89-A3D6-A37998FB86B0";
    options.ResponseType = "code";
    options.UsePkce = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.SaveTokens = true;
    options.RequireHttpsMetadata = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.ClaimActions.MapAll();
});

builder.Services.AddAuthorization();


var app = builder.Build();


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}


app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Minimal API endpoints for login and logout
app.MapGet("/login", (HttpContext context) =>
{
    if (!context.User.Identity?.IsAuthenticated ?? true)
    {
        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, new[] { "oidc" });
    }
    else
    {
        return Results.Redirect("/");
    }
});

app.MapGet("/logout", async (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated ?? false)
    {
        await context.SignOutAsync("oidc", new AuthenticationProperties { RedirectUri = "/" });
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
    else
    {
        context.Response.Redirect("/");
    }
});



app.UseAntiforgery();


app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
