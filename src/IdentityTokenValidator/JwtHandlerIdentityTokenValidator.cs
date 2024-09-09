// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient
{
    /// <inheritdoc />
    public class JwtHandlerIdentityTokenValidator : IIdentityTokenValidator
    {
        /// <inheritdoc />
#pragma warning disable 1998
        public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default)
#pragma warning restore 1998
        {
            var logger = options.LoggerFactory.CreateLogger<JwtHandlerIdentityTokenValidator>();
         
            logger.LogTrace("Validate");
            
            // setup general validation parameters
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = options.ProviderInformation.IssuerName,
                ValidAudience = options.ClientId,
                ValidateIssuer = options.Policy.ValidateTokenIssuerName,
                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,

                ClockSkew = options.ClockSkew
            };

            // read the token signing algorithm
            var handler = new JsonWebTokenHandler();
            JsonWebToken jwt;

            try
            {
                jwt = handler.ReadJsonWebToken(identityToken);
            }
            catch (Exception ex)
            {
                return new IdentityTokenValidationResult
                {
                    Error = $"Error validating identity token: {ex.ToString()}"
                };
            }

            var algorithm = jwt.Alg;
            
            // if token is unsigned, and this is allowed, skip signature validation
            if (string.Equals(algorithm, "none", StringComparison.OrdinalIgnoreCase))
            {
                if (options.Policy.RequireIdentityTokenSignature)
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = $"Identity token is not signed. Signatures are required by policy"
                    };
                }
                else
                {
                    logger.LogInformation("Identity token is not signed. This is allowed by configuration.");
                    parameters.RequireSignedTokens = false;
                }
            }
            else
            {
                // check if signature algorithm is allowed by policy
                if (!options.Policy.ValidSignatureAlgorithms.Contains(algorithm))
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = $"Identity token uses invalid algorithm: {algorithm}"
                    };
                };
            }

            var result = await ValidateSignatureAsync(identityToken, handler, parameters, options, logger);
            if (result.IsValid == false)
            {
                if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                {
                    logger.LogWarning("Key for validating token signature cannot be found. Refreshing keyset.");

                    return new IdentityTokenValidationResult
                    {
                        Error = "invalid_signature"
                    };
                }

                if (result.Exception is SecurityTokenValidationException)
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = "unable_to_validate_token"
                    };
                }

                throw result.Exception;
            }

            var user = new ClaimsPrincipal(result.ClaimsIdentity);
            
            var error = CheckRequiredClaim(user);
            if (error.IsPresent())
            {
                return new IdentityTokenValidationResult
                {
                    Error = error
                };
            }

            return new IdentityTokenValidationResult
            {
                User = user,
                SignatureAlgorithm = algorithm
            };
        }

        private async Task<TokenValidationResult> ValidateSignatureAsync(string identityToken, JsonWebTokenHandler handler, TokenValidationParameters parameters, OidcClientOptions options, ILogger logger)
        {
            if (parameters.RequireSignedTokens)
            {
                // read keys from provider information
                var keys = new List<SecurityKey>();

                foreach (var webKey in options.ProviderInformation.KeySet.Keys)
                {
                    if (webKey.E.IsPresent() && webKey.N.IsPresent())
                    {
                        // only add keys used for signatures
                        if (webKey.Use == "sig" || webKey.Use == null)
                        {
                            var e = Base64Url.Decode(webKey.E);
                            var n = Base64Url.Decode(webKey.N);

                            var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                            key.KeyId = webKey.Kid;

                            keys.Add(key);

                            logger.LogDebug("Added signing key with kid: {kid}", key?.KeyId ?? "not set");
                        }
                    }
                    else if (webKey.X.IsPresent() && webKey.Y.IsPresent() && webKey.Crv.IsPresent())
                    {
                        var ec = ECDsa.Create(new ECParameters
                        {
                            Curve = GetCurveFromCrvValue(webKey.Crv),
                            Q = new ECPoint
                            {
                                X = Base64Url.Decode(webKey.X),
                                Y = Base64Url.Decode(webKey.Y)
                            }
                        });

                        var key = new ECDsaSecurityKey(ec);
                        key.KeyId = webKey.Kid;

                        keys.Add(key);
                    }
                    else
                    {
                        logger.LogDebug("Signing key with kid: {kid} currently not supported", webKey.Kid ?? "not set");
                    }
                }

                parameters.IssuerSigningKeys = keys;
            }
            
            return await handler.ValidateTokenAsync(identityToken, parameters);
        }

        private static string CheckRequiredClaim(ClaimsPrincipal user)
        {
            var requiredClaims = new List<string>
            {
                JwtClaimTypes.Issuer,
                JwtClaimTypes.Subject,
                JwtClaimTypes.IssuedAt,
                JwtClaimTypes.Audience,
                JwtClaimTypes.Expiration,
            };

            foreach (var claimType in requiredClaims)
            {
                var claim = user.FindFirst(claimType);
                if (claim == null)
                {
                    return $"{claimType} claim is missing";
                }
            }

            return null;
        }

        internal static ECCurve GetCurveFromCrvValue(string crv)
        {
            switch (crv)
            {
                case JsonWebKeyECTypes.P256:
                    return ECCurve.NamedCurves.nistP256;
                case JsonWebKeyECTypes.P384:
                    return ECCurve.NamedCurves.nistP384;
                case JsonWebKeyECTypes.P521:
                    return ECCurve.NamedCurves.nistP521;
                default:
                    throw new InvalidOperationException($"Unsupported curve type of {crv}");
            }
        }
    }
}