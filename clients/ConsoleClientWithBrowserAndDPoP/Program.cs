using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog.Sinks.SystemConsole.Themes;
using IdentityModel.OidcClient.DPoP;

namespace ConsoleClientWithBrowserAndDPoP
{
    public class Program
    {
        static readonly string Api = "https://demo.duendesoftware.com/api/dpop/test";
        static readonly string Authority = "https://demo.duendesoftware.com";

        private static OidcClient _oidcClient;
        private static HttpClient _apiClient = new HttpClient { BaseAddress = new Uri(Api) };

        public static async Task Main()
        {
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("|  Sign in with OIDC    |");
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("");
            Console.WriteLine("Press any key to sign in...");
            Console.ReadKey();

            await SignIn();
        }

        private static async Task SignIn()
        {
            var browser = new SystemBrowser();
            string redirectUri = string.Format($"http://127.0.0.1:{browser.Port}");

            var proofKey = GetProofKey();
            
            var options = new OidcClientOptions
            {
                Authority = Authority,
                ClientId = "native.dpop",
                RedirectUri = redirectUri,
                Scope = "openid profile api offline_access",
                FilterClaims = false,
                Browser = browser,
            };

            options.ConfigureDPoP(proofKey); 
            
            var serilog = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .Enrich.FromLogContext()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);

            _oidcClient = new OidcClient(options);

            LoginResult result = null;
            if (File.Exists("refresh_token"))
            {
                var refreshToken = File.ReadAllText("refresh_token");
                var handler = _oidcClient.CreateDPoPHandler(proofKey, refreshToken);
                
                _apiClient = new HttpClient(handler)
                {
                    BaseAddress = new Uri(Api)
                };
                
                await NextSteps();
            }
            else
            {
                 result = await _oidcClient.LoginAsync(new LoginRequest());
                 File.WriteAllText("refresh_token", result.TokenResponse.RefreshToken);

                _apiClient = new HttpClient(result.RefreshTokenHandler)
                {
                    BaseAddress = new Uri(Api)
                };
            }
            
            

            ShowResult(result);
            await NextSteps();
        }

        private static string GetProofKey()
        {
            if (File.Exists("proofkey"))
            {
                return File.ReadAllText("proofkey");
            }
            
            var proofKey = JsonWebKeys.CreateRsaJson();
            File.WriteAllText("proofkey", proofKey);
            return proofKey;
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

            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result.TokenResponse.Raw);

            Console.WriteLine($"token response...");
            foreach (var item in values)
            {
                Console.WriteLine($"{item.Key}: {item.Value}");
            }
        }

        private static async Task NextSteps()
        {
            var menu = "  x...exit  c...call api   ";
            
            while (true)
            {
                Console.WriteLine("\n\n");

                Console.Write(menu);
                var key = Console.ReadKey();

                if (key.Key == ConsoleKey.X) return;
                if (key.Key == ConsoleKey.C) await CallApi();
            }
        }

        private static async Task CallApi()
        {
            var response = await _apiClient.GetAsync("");

            if (response.IsSuccessStatusCode)
            {
                var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Console.WriteLine("\n\n");
                Console.WriteLine(json.RootElement);
            }
            else
            {
                Console.WriteLine($"Error: {response.ReasonPhrase}");
            }
        }


    }
}