using Idp;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
        .Enrich.FromLogContext()
        .ReadFrom.Configuration(ctx.Configuration));

    var origin = new Uri("https://localhost:5001");
    builder.Services.AddFido2(options =>
    {
        options.ServerDomain = origin.Host;
        options.ServerName = "FIDO2 Server";
        options.Origins = new HashSet<string> { origin.AbsoluteUri };
        options.TimestampDriftTolerance = 1000;
    });

    builder.Services.AddControllers();


    var app = builder
        .ConfigureServices()
        .ConfigurePipeline();


    app.MapControllers();
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}