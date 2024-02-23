## About IdentityModel.OidcClient
IdentityModel.OidcClient.IdentityTokenValidator validates ID tokens using Microsoft's
[System.IdentityModel.Tokens.Jwt](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/)
library. It is intended to be used with
[IdentityModel.OidcClient](https://www.nuget.org/packages/IdentityModel.OidcClient/),
which provides an abstraction for validation of ID tokens that this package implements.
Distributing the ID token validator separately allows for greater control of the version
of the Microsoft JWT handler and prevents certain dependency issues. 

## Related Packages

- Library for claims-based identity, OAuth 2.0, and OpenID Connect: [IdentityModel](https://www.nuget.org/packages/IdentityModel)
- RFC8252 compliant and certified OpenID Connect and OAuth 2.0 client library for native applications: [IdentityModel.OidcClient](https://www.nuget.org/packages/IdentityModel.OidcClient)
- Id token validator for IdentityModel.OidcClient based on the Microsoft JWT handler: [IdentityModel.OidcClient.IdentityTokenValidator](https://www.nuget.org/packages/IdentityModel.OidcClient.IdentityTokenValidator)
- Authentication handler for introspection tokens: [IdentityModel.AspNetCore.OAuth2Introspection](https://www.nuget.org/packages/IdentityModel.AspNetCore.OAuth2Introspection)

## Feedback

IdentityModel.OidcClient.IdentityTokenValidator is released as open source under the 
[Apache 2.0 license](https://github.com/IdentityModel/IdentityModel.OidcClient/blob/main/LICENSE). 
Bug reports and contributions are welcome at 
[the GitHub repository](https://github.com/IdentityModel/IdentityModel.OidcClient).
