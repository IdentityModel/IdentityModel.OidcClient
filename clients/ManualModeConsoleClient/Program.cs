// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.OidcClient;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

Console.WriteLine("+-----------------------+");
Console.WriteLine("|  Sign in with OIDC    |");
Console.WriteLine("+-----------------------+");
Console.WriteLine("");
Console.WriteLine("Press any key to sign in...");
Console.ReadKey();

SignIn();

Console.ReadKey();

async void SignIn()
{
    // create a redirect URI using an available port on the loopback address.
    string redirectUri = string.Format("http://127.0.0.1:7890/");
    Console.WriteLine("redirect URI: " + redirectUri);

    // create an HttpListener to listen for requests on that redirect URI.
    var http = new HttpListener();
    http.Prefixes.Add(redirectUri);
    Console.WriteLine("Listening..");
    http.Start();

    var options = new OidcClientOptions
    {
        Authority = "https://demo.duendesoftware.com",
        ClientId = "interactive.public",
        Scope = "openid profile api",
        RedirectUri = redirectUri,
    };

    var client = new OidcClient(options);
    var state = await client.PrepareLoginAsync();

    if(state.IsError)
    {
        Console.WriteLine($"Failed to create authentication state: {state.Error} - {state.ErrorDescription}");
        http.Stop();
        return;
    }

    Console.WriteLine($"Start URL: {state.StartUrl}");

    // open system browser to start authentication
    Process.Start(new ProcessStartInfo
    {
        FileName = state.StartUrl,
        UseShellExecute = true,
    });
    
    // wait for the authorization response.
    var context = await http.GetContextAsync();

    // sends an HTTP response to the browser.
    var response = context.Response;
    string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://demo.duendesoftware.com'></head><body>Please return to the app.</body></html>");
    var buffer = Encoding.UTF8.GetBytes(responseString);
    response.ContentLength64 = buffer.Length;
    var responseOutput = response.OutputStream;
    await responseOutput.WriteAsync(buffer, 0, buffer.Length);
    responseOutput.Close();

    var result = await client.ProcessResponseAsync(context.Request.RawUrl, state);

    BringConsoleToFront();

    if (result.IsError)
    {
        Console.WriteLine("\n\nError:\n{0}", result.Error);
    }
    else
    {
        Console.WriteLine("\n\nClaims:");
        foreach (var claim in result.User.Claims)
        {
            Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
        }

        Console.WriteLine();
        Console.WriteLine("Access token:\n{0}", result.AccessToken);

        if (!string.IsNullOrWhiteSpace(result.RefreshToken))
        {
            Console.WriteLine("Refresh token:\n{0}", result.RefreshToken);
        }
    }

    http.Stop();
}

// Hack to bring the Console window to front.
// ref: http://stackoverflow.com/a/12066376
[DllImport("kernel32.dll", ExactSpelling = true)]
static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool SetForegroundWindow(IntPtr hWnd);

void BringConsoleToFront()
{
    SetForegroundWindow(GetConsoleWindow());
}
