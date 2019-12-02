// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    internal class IdentityTokenValidator
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;
        private readonly Func<CancellationToken, Task> _refreshKeysAsync;

        public IdentityTokenValidator(OidcClientOptions options, Func<CancellationToken, Task> refreshKeysAsync)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<IdentityTokenValidator>();
            _refreshKeysAsync = refreshKeysAsync;
        }

        /// <summary>
        /// Validates the specified identity token.
        /// </summary>
        /// <param name="identityToken">The identity token.</param>
        /// <param name="cancellationToken">A token that can be used to cancel the request</param>
        /// <returns>The validation result</returns>
        public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("Validate");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            // setup general validation parameters
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _options.ProviderInformation.IssuerName,
                ValidAudience = _options.ClientId,
                ValidateIssuer = _options.Policy.ValidateTokenIssuerName,
                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,

                ClockSkew = _options.ClockSkew
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
                if (_options.Policy.RequireIdentityTokenSignature)
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = $"Identity token is not singed. Signatures are required by policy"
                    };
                }
                else
                {
                    _logger.LogInformation("Identity token is not signed. This is allowed by configuration.");
                    parameters.RequireSignedTokens = false;
                }
            }
            else
            {
                // check if signature algorithm is allowed by policy
                if (!_options.Policy.ValidSignatureAlgorithms.Contains(algorithm))
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
                user = ValidateSignature(identityToken, handler, parameters);
            }
            catch (SecurityTokenSignatureKeyNotFoundException sigEx)
            {
                if (_options.RefreshDiscoveryOnSignatureFailure)
                {
                    _logger.LogWarning("Key for validating token signature cannot be found. Refreshing keyset.");

                    // try to refresh the key set and try again
                    await _refreshKeysAsync(cancellationToken);

                    try
                    {
                        user = ValidateSignature(identityToken, handler, parameters);
                    }
                    catch (Exception ex)
                    {
                        return new IdentityTokenValidationResult
                        {
                            Error = $"Error validating identity token: {ex.ToString()}"
                        };
                    }
                }
                else
                {
                    return new IdentityTokenValidationResult
                    {
                        Error = $"Error validating identity token: {sigEx.ToString()}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new IdentityTokenValidationResult
                {
                    Error = $"Error validating identity token: {ex.ToString()}"
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

        private ClaimsPrincipal ValidateSignature(string identityToken, JwtSecurityTokenHandler handler, TokenValidationParameters parameters)
        {
            if (parameters.RequireSignedTokens)
            {
                // read keys from provider information
                var keys = new List<SecurityKey>();

                foreach (var webKey in _options.ProviderInformation.KeySet.Keys)
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

                            _logger.LogDebug("Added signing key with kid: {kid}", key?.KeyId ?? "not set");
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
                        _logger.LogDebug("Signing key with kid: {kid} currently not supported", webKey.Kid ?? "not set");
                    }
                }

                parameters.IssuerSigningKeys = keys;
            }

            SecurityToken token;
            return handler.ValidateToken(identityToken, parameters, out token);
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