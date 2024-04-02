## About IdentityModel.OidcClient
IdentityModel.OidcClient is an OpenID Connect (OIDC) client library for native
applications. It provides
- Types that describe OIDC requests and responses
- Low level methods to construct protocol state and handle responses
- Higher level methods for 
   - Logging in
   - Logging out
   - Retrieving userinfo
   - Refreshing tokens

## Samples
IdentityModel.OidcClient targets .NET Standard, making it suitable for .NET and .NET
Framework. It can be used to build OIDC native clients with a variety of .NET UI tools.
The [samples repository](https://github.com/IdentityModel/IdentityModel.OidcClient.Samples)
shows how to use it in 
- .NET MAUI
- WPF with the system browser
- WPF with an embedded browser
- WinForms with an embedded browser
- Cross Platform Console Applications (relies on kestrel for processing the callback)
- Windows Console Applications (relies on an HttpListener - a wrapper around the windows HTTP.sys driver)
- Windows Console Applications using custom uri schemes

## Documentation 

More documentation is available
[here](https://identitymodel.readthedocs.io/en/latest/native/overview.html).


## Standards and Certification
IdentityModel.OidcClient is a [certified](http://openid.net/certification/) OpenID Connect
relying party implementation, and implements [RFC 8252](https://tools.ietf.org/html/rfc8252/),
"OAuth 2.0 for native Applications".

![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)




## Related Packages

- Library for claims-based identity, OAuth 2.0, and OpenID Connect: [IdentityModel](https://www.nuget.org/packages/IdentityModel)
- Id token validator for IdentityModel.OidcClient based on the Microsoft JWT handler: [IdentityModel.OidcClient.IdentityTokenValidator](https://www.nuget.org/packages/IdentityModel.OidcClient.IdentityTokenValidator)
- [DPoP](https://datatracker.ietf.org/doc/html/rfc9449) extensions for IdentityModel.OidcClient: [IdentityModel.OidcClient.DPoP ](https://www.nuget.org/packages/IdentityModel.OidcClient.DPoP)
- Authentication handler for introspection tokens: [IdentityModel.AspNetCore.OAuth2Introspection](https://www.nuget.org/packages/IdentityModel.AspNetCore.OAuth2Introspection)

## Feedback

IdentityModel.OidcClient is released as open source under the 
[Apache 2.0 license](https://github.com/IdentityModel/IdentityModel.OidcClient/blob/main/LICENSE). 
Bug reports and contributions are welcome at 
[the GitHub repository](https://github.com/IdentityModel/IdentityModel.OidcClient).
