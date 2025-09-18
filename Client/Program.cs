using Client.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = "oidc";
})
.AddCookie("Cookies")
.AddOpenIdConnect("oidc", options =>
{
    var authSection = builder.Configuration.GetSection("Authentication");
    options.Authority = authSection["Authority"] ?? "https://localhost:5001";
    options.ClientId = authSection["ClientId"] ?? "blazor-client";
    options.ClientSecret = authSection["ClientSecret"] ?? "secret";
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    
    // Use configuration for RequireHttpsMetadata
    options.RequireHttpsMetadata = authSection.GetValue<bool?>("RequireHttpsMetadata") ?? true;
});

builder.Services.AddAuthorization();

// Add cascading authentication state provider
builder.Services.AddCascadingAuthenticationState();

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

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add authentication endpoints
app.MapGet("/Login", (string? returnUrl) =>
    Results.Challenge(new Microsoft.AspNetCore.Authentication.AuthenticationProperties
    {
        RedirectUri = returnUrl ?? "/"
    }, new[] { "oidc" }));

app.MapPost("/Logout", () =>
    Results.SignOut(
        new Microsoft.AspNetCore.Authentication.AuthenticationProperties
        {
            RedirectUri = "/"
        },
        new[] { "Cookies", "oidc" }));

app.Run();
