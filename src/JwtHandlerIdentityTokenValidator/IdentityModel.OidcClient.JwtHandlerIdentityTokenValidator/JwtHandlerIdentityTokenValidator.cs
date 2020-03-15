using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient
{
    public class JwtHandlerIdentityTokenValidator : IIdentityTokenValidator
    {
        public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default)
        {
            var logger = options.LoggerFactory.CreateLogger<JwtHandlerIdentityTokenValidator>();
         
            logger.LogTrace("Validate");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

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
            JwtSecurityToken jwt;

            try
            {
                jwt = handler.ReadJwtToken(identityToken);
            }
            catch (Exception ex)
            {
                return new IdentityTokenValidationResult
                {
                    Error = $"Error validating identity token: {ex.ToString()}"
                };
            }

            var algorithm = jwt.Header.Alg;

            // if token is unsigned, and this is allowed, skip signature validation
            if (string.Equals(algorithm, "none"))
            {
                if (options.Policy.RequireIdentityTokenSignature)
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = $"Identity token is not singed. Signatures are required by policy"
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

            ClaimsPrincipal user;
            try
            {
                user = ValidateSignature(identityToken, handler, parameters, options, logger);
            }
            catch (SecurityTokenSignatureKeyNotFoundException sigEx)
            {
                logger.LogWarning("Key for validating token signature cannot be found. Refreshing keyset.");
                
                return new IdentityTokenValidationResult
                {
                    Error = "invalid_signature"
                };
            }
            
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

        private ClaimsPrincipal ValidateSignature(string identityToken, JwtSecurityTokenHandler handler, TokenValidationParameters parameters, OidcClientOptions options, ILogger logger)
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
            
            return handler.ValidateToken(identityToken, parameters, out _);
        }

        private string CheckRequiredClaim(ClaimsPrincipal user)
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