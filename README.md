# C#/NetStandard OpenID Connect Client Library for native Applications
Supported platforms: netstandard14, desktop .NET, .NET Core, Xamarin iOS & Android

## Description

OidcClient is an implemenation of the OIDC/OAuth 2 for native apps [specification](https://tools.ietf.org/wg/oauth/draft-ietf-oauth-native-apps/) for C#.

### "Manual" Mode
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
