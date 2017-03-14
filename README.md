# C#/NetStandard OpenID Connect Client Library for native Applications
Supported platforms: netstandard14, desktop .NET, UWP, .NET Core, Xamarin iOS & Android. [Nuget.](https://www.nuget.org/packages/IdentityModel.OidcClient/)

[Certified](http://openid.net/certification/) OpenID Connect relying party implementation. 

![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)

## Description

OidcClient is an implemenation of the OIDC/OAuth 2 for native apps [specification](https://tools.ietf.org/wg/oauth/draft-ietf-oauth-native-apps/) for C#.

### Manual Mode
In manual mode, OidcClient helps you with creating the necessary start URL and state parameters, but you need to coordinate with whatever browser you want to use, e.g.

```csharp
var options = new OidcClientOptions
{
    Authority = _authority,
    ClientId = "native.hybrid",
    RedirectUri = redirectUri,
    Scope = "openid profile api"
};

var client = new OidcClient(options);

// generate start URL, state, nonce, code challenge
var state = await client.PrepareLoginAsync();
```

When the browser work is done, OidcClient can take over to process the response, get the access/refresh tokens, contact userinfo endpoint etc..

```csharp
var result = await client.ProcessResponseAsync(data, state);
```

The result will contain the tokens and the claims of the user.

### Automatic Mode
In automatic mode, you can encapsulate all browser interactions by implementing the `IBrowser` interface. 

```csharp
var options = new OidcClientOptions
{
    Authority = _authority,
    ClientId = "native.hybrid",
    RedirectUri = redirectUri,
    Scope = "openid profile api",
    Browser = new SystemBrowser(port: 7890)
};

var client = new OidcClient(options);
```

Once that is done, authentication and token requests become one line of code:

```csharp
var result = await client.LoginAsync();
```

### Logging
OidcClient has support for the standard .NET logging facilities, e.g. using Serilog:

```csharp
var serilog = new LoggerConfiguration()
    .MinimumLevel.Verbose()
    .Enrich.FromLogContext()
    .WriteTo.LiterateConsole(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
    .CreateLogger();

options.LoggerFactory.AddSerilog(serilog);
```

### Samples
See [here](https://github.com/IdentityModel/IdentityModel.OidcClient.Samples) for samples using WinForms, Console and Xamarin iOS/Android.
