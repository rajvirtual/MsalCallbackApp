using Microsoft.Identity.Client;
using System.Security.Cryptography.X509Certificates;

string RedirectUri = "https://localhost:7269/callback";
string CertPath = @"C:\Dev\cert.pfx";

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    // Add a route for the callback
    _ = endpoints.MapGet("/callback", async context =>
    {
        var query = context.Request.QueryString.Value;

        var certificate = new X509Certificate2(CertPath);

        var authCode = context.Request.Query["code"].ToString();

        try
        {
            var scopeSCBackend = new string[] { "api://ee347c0f-f282-4036-8236-fff75f2e68df/examplescopebackend" };

            IConfidentialClientApplication confidentialClientSCClient = ConfidentialClientApplicationBuilder.Create("72826068-14ca-40fb-a5a6-f1737faf458f")
                   .WithAuthority(AzureCloudInstance.AzurePublic, "72f988bf-86f1-41af-91ab-2d7cd011db47")
                   .WithRedirectUri(RedirectUri)
                   .WithCertificate(certificate)
                   .Build();


            var result = await confidentialClientSCClient.AcquireTokenByAuthorizationCode(scopeSCBackend, authCode)
                        .WithSendX5C(true)
                       .ExecuteAsync();

            UserAssertion userAssertion = new UserAssertion(result.AccessToken);

            IConfidentialClientApplication confidentialClientSCBackend = ConfidentialClientApplicationBuilder.Create("ee347c0f-f282-4036-8236-fff75f2e68df")
                         .WithAuthority(AzureCloudInstance.AzurePublic, "d6ef095c-bab3-44e5-a20c-3484b3407046")
                         .WithRedirectUri(RedirectUri)
                         .WithCertificate(certificate)
                         .Build();

            var scopeTargetBackend = new string[] { "api://024a61dc-2529-4609-99ea-40cc8ba8d756/examplescope" };

            AuthenticationResult rpSCBackendResult = await confidentialClientSCBackend
            .AcquireTokenOnBehalfOf(scopeTargetBackend, userAssertion)
            .WithSendX5C(true)
            .ExecuteAsync();

            Console.WriteLine(rpSCBackendResult.AccessToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }

        await context.Response.WriteAsync($"Callback received. Query string: {query}");
    });

    // Default route
    _ = endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
});


app.MapRazorPages();

app.Run();
