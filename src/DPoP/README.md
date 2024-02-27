## About IdentityModel.OidcClient
IdentityModel.OidcClient.DPoP adds support for DPoP ([RFC
9449](https://datatracker.ietf.org/doc/html/rfc9449)) to IdentityModel.OidcClient. DPoP
sender-constrains access and refresh tokens to protect them against replay attacks, and is 
often used by mobile and other native applications.

## Related Packages

- Library for claims-based identity, OAuth 2.0, and OpenID Connect: [IdentityModel](https://www.nuget.org/packages/IdentityModel)
- RFC8252 compliant and certified OpenID Connect and OAuth 2.0 client library for native applications: [IdentityModel.OidcClient](https://www.nuget.org/packages/IdentityModel.OidcClient)
- Id token validator for IdentityModel.OidcClient based on the Microsoft JWT handler: [IdentityModel.OidcClient.IdentityTokenValidator](https://www.nuget.org/packages/IdentityModel.OidcClient.IdentityTokenValidator)
- Authentication handler for introspection tokens: [IdentityModel.AspNetCore.OAuth2Introspection](https://www.nuget.org/packages/IdentityModel.AspNetCore.OAuth2Introspection)

## Feedback

IdentityModel.OidcClient is released as open source under the 
[Apache 2.0 license](https://github.com/IdentityModel/IdentityModel.OidcClient/blob/main/LICENSE). 
Bug reports and contributions are welcome at 
[the GitHub repository](https://github.com/IdentityModel/IdentityModel.OidcClient).
