using Client.Components;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add controller services
builder.Services.AddControllers();

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    var authConfig = builder.Configuration.GetSection("Authentication");
    
    options.Authority = authConfig["Authority"];
    options.ClientId = authConfig["ClientId"];
    options.ClientSecret = authConfig["ClientSecret"];
    options.ResponseType = authConfig["ResponseType"] ?? "code";
    options.SaveTokens = bool.Parse(authConfig["SaveTokens"] ?? "true");
    options.GetClaimsFromUserInfoEndpoint = bool.Parse(authConfig["GetClaimsFromUserInfoEndpoint"] ?? "true");
    options.RequireHttpsMetadata = bool.Parse(authConfig["RequireHttpsMetadata"] ?? "false");
    
    // Add scopes
    var scopes = authConfig["Scope"]?.Split(' ') ?? new[] { "openid", "profile" };
    foreach (var scope in scopes)
    {
        options.Scope.Add(scope);
    }
    
    // Configure redirect URLs
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";
});

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

app.UseAntiforgery();

app.MapControllers();
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
