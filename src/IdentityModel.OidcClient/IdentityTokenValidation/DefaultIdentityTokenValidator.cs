// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;
using System.Linq;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    public class DefaultIdentityTokenValidator : IIdentityTokenValidator
    {
        //private static readonly ILog Logger = LogProvider.For<DefaultIdentityTokenValidator>();

        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, DiscoveryResponse disco)
        {
            //Logger.Debug("starting identity token validation");
            //Logger.Debug($"identity token: {identityToken}");

            var fail = new IdentityTokenValidationResult
            {
                Success = false
            };

            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                key.KeyId = webKey.Kid;

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = disco.TryGetString(OidcConstants.Discovery.Issuer),
                ValidAudience = clientId,
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                SecurityToken token;

                var principal = handler.ValidateToken(identityToken, parameters, out token);

                return Task.FromResult(new IdentityTokenValidationResult
                {
                    Success = true,
                    User = principal,
                    SignatureAlgorithm = "RS256"
                });
            }
            catch (Exception ex)
            {
                return Task.FromResult(new IdentityTokenValidationResult
                {
                    Success = false,
                    Error = ex.Message
                });
            }
        }
    }
}