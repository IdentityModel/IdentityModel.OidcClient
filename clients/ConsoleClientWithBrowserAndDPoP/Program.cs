﻿using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog.Sinks.SystemConsole.Themes;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;
using System.Security.Cryptography;
using IdentityModel.DPoP;

namespace ConsoleClientWithBrowserAndDPoP
{
    public class Program
    {
        //static string _api = "https://demo.duendesoftware.com/api/dpop/test";
        static string _api = "https://localhost:5002/api/dpop/test";
        
        //static string authority = "https://demo.duendesoftware.com";
        static string authority = "https://localhost:5001";

        static OidcClient _oidcClient;
        static HttpClient _apiClient = new HttpClient { BaseAddress = new Uri(_api) };

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
            // create a redirect URI using an available port on the loopback address.
            // requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port
            var browser = new SystemBrowser();
            string redirectUri = string.Format($"http://127.0.0.1:{browser.Port}");

            var key = new RsaSecurityKey(RSA.Create(2048))
            {
                KeyId = CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)
            };
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            jwk.Alg = "RS256";
            var jwkJson = JsonSerializer.Serialize(jwk);
            var tokenDpopHandler = new ProofTokenMessageHandler(jwkJson, new SocketsHttpHandler());
            var apiDpopHandler = new ProofTokenMessageHandler(jwkJson, new SocketsHttpHandler());

            var options = new OidcClientOptions
            {
                Authority = authority,
                //ClientId = "interactive.public.short",
                ClientId = "dpop.native",
                RedirectUri = redirectUri,
                Scope = "openid profile api offline_access",
                FilterClaims = false,

                Browser = browser,
                IdentityTokenValidator = new JwtHandlerIdentityTokenValidator(),
                BackchannelHandler = tokenDpopHandler,
                RefreshTokenInnerHttpHandler = apiDpopHandler
            };

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .Enrich.FromLogContext()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);

            _oidcClient = new OidcClient(options);
            var result = await _oidcClient.LoginAsync(new LoginRequest());

            _apiClient = new HttpClient(result.RefreshTokenHandler)
            {
                BaseAddress = new Uri(_api)
            };

            ShowResult(result);
            await NextSteps(result);
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

        private static async Task NextSteps(LoginResult result)
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