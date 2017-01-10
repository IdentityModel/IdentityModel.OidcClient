using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Threading.Tasks;

namespace ConsoleClientWithBrowser
{
    public class Program
    {
        static string _authority = "https://demo.identityserver.io";
        static string _api = "https://api.identityserver.io/identity";

        public static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();

        public static async Task MainAsync()
        {
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("|  Sign in with OIDC    |");
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("");
            Console.WriteLine("Press any key to sign in...");
            Console.ReadKey();

            await SignInAsync();

            Console.ReadKey();
        }

        private static async Task SignInAsync()
        {
            // create a redirect URI using an available port on the loopback address.
            string redirectUri = string.Format("http://127.0.0.1:7890/");

            var options = new OidcClientOptions
            {
                Authority = _authority,
                ClientId = "native.hybrid",
                RedirectUri = redirectUri,
                Scope = "openid profile api",
                FilterClaims = true,
                LoadProfile = true,
                Flow = OidcClientOptions.AuthenticationFlow.Hybrid,
                Browser = new SystemBrowser(port: 7890)
            };

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.LiterateConsole(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            ShowResult(result);
        }

        private static void ShowResult(LoginResult result)
        {
            if (result.IsError)
            {
                Console.WriteLine("\n\nError:\n{0}", result.Error);
                return;
            }

            Console.WriteLine("\n\nClaims:");
            foreach (var claim in result.User.Claims)
            {
                Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
            }

            Console.WriteLine($"\nidentity token: {result.IdentityToken}");
            Console.WriteLine($"access token:   {result.AccessToken}");
            Console.WriteLine($"refresh token:  {result?.RefreshToken ?? "none"}");
        }
    }
}
