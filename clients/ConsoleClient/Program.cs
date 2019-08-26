using IdentityModel.OidcClient;
using Microsoft.Net.Http.Server;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleClient
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

        private async static Task SignInAsync()
        {
            // create a redirect URI using an available port on the loopback address.
            string redirectUri = string.Format("http://127.0.0.1:7890/");

            // create an HttpListener to listen for requests on that redirect URI.
            var settings = new WebListenerSettings();
            settings.UrlPrefixes.Add(redirectUri);
            var http = new WebListener(settings);

            http.Start();
            Console.WriteLine("Listening..");
            
            var options = new OidcClientOptions
            {
                Authority = _authority,
                ClientId = "native.hybrid",
                RedirectUri = redirectUri,
                Scope = "openid profile api",
                FilterClaims = true,
                LoadProfile = true,
                Flow = OidcClientOptions.AuthenticationFlow.Hybrid
            };

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.LiterateConsole(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);

            var client = new OidcClient(options);
            var state = await client.PrepareLoginAsync();

            OpenBrowser(state.StartUrl);

            var context = await http.AcceptAsync();
            var formData = GetRequestPostData(context.Request);

            if (formData == null)
            {
                Console.WriteLine("Invalid response");
                return;
            }

            await SendResponseAsync(context.Response);

            var result = await client.ProcessResponseAsync(formData, state);

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

            var values = JsonConvert.DeserializeObject<Dictionary<string, string>>(result.TokenResponse.Raw);

            Console.WriteLine($"Raw TokenResponse ...");
            foreach (var item in values)
            {
                Console.WriteLine($"{item.Key}: {item.Value}");
            }

        }

        private static async Task SendResponseAsync(Response response)
        {
            string responseString = $"<html><head></head><body>Please return to the app.</body></html>";
            var buffer = Encoding.UTF8.GetBytes(responseString);

            response.ContentLength = buffer.Length;

            var responseOutput = response.Body;
            await responseOutput.WriteAsync(buffer, 0, buffer.Length);
            responseOutput.Flush();
        }

        public static void OpenBrowser(string url)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }

        public static string GetRequestPostData(Request request)
        {
            if (!request.HasEntityBody)
            {
                return null;
            }

            using (var body = request.Body)
            {
                using (var reader = new StreamReader(body))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
