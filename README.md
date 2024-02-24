## About IdentityModel.OidcClient
This repository contains several libraries for building OpenID Connect (OIDC) native
clients. The core IdentityModel.OidcClient library is a certified OIDC relying party and
implements [RFC 8252](https://tools.ietf.org/html/rfc8252/), "OAuth 2.0 for native
Applications". The IdentityModel.OidcClient.IdTokenValidator provides validation of Id
Tokens based on the Microsoft JWT handler: 
[IdentityModel.OidcClient.IdentityTokenValidator](https://www.nuget.org/packages/IdentityModel.OidcClient.IdentityTokenValidator),
and is distributed as a separate package in order to prevent certain dependency problems.
Finally, IdentityModel.OidcClient.DPoP adds [DPoP](https://datatracker.ietf.org/doc/html/rfc9449) 
extensions to IdentityModel.OidcClient for sender-constraining tokens.


## Samples
OidcClient targets .NET Standard, making it suitable for .NET and .NET
Framework. It can be used to build OIDC native clients with a variety of .NET UI tools.
The [samples repository](https://github.com/IdentityModel/IdentityModel.OidcClient.Samples)
shows how to use it in 
- .NET MAUI
- Console Applications
- WPF
- WinForms
- Xamarin iOS & Android
- UWP

## Documentation 

More documentation is available
[here](https://identitymodel.readthedocs.io/en/latest/native/overview.html).


## Certification
OidcClient is a [certified](http://openid.net/certification/) OpenID Connect
relying party implementation.

![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)


## Feedback

IdentityModel.OidcClient is released as open source under the 
[Apache 2.0 license](https://github.com/IdentityModel/IdentityModel.OidcClient/blob/main/LICENSE). 
Bug reports and contributions are welcome at 
[the GitHub repository](https://github.com/IdentityModel/IdentityModel.OidcClient).
