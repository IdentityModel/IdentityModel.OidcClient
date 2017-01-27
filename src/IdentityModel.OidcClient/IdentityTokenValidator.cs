using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IdentityModel.OidcClient
{
    internal class IdentityTokenValidator
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;

        public IdentityTokenValidator(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<IdentityTokenValidator>();
        }

        /// <summary>
        /// Validates the specified identity token.
        /// </summary>
        /// <param name="identityToken">The identity token.</param>
        /// <returns>The validation result</returns>
        public IdentityTokenValidationResult Validate(string identityToken)
        {
            _logger.LogTrace("Validate");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            // setup general validation parameters
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _options.ProviderInformation.IssuerName,
                ValidAudience = _options.ClientId,

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
                _logger.LogError(ex.ToString());

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

                // read keys from provide information
                var keys = new List<SecurityKey>();
                foreach (var webKey in _options.ProviderInformation.KeySet.Keys)
                {
                    // todo
                    if (webKey.E.IsPresent() && webKey.N.IsPresent())
                    {
                        var e = Base64Url.Decode(webKey.E);
                        var n = Base64Url.Decode(webKey.N);

                        var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                        key.KeyId = webKey.Kid;

                        keys.Add(key);

                        _logger.LogDebug("Added signing key with kid: {kid}", key?.KeyId ?? "not set");
                    }
                    else
                    {
                        _logger.LogDebug("Signing key with kid: {kid} currently not supported", webKey.Kid ?? "not set");
                    }
                }

                parameters.IssuerSigningKeys = keys;
            }
            
            SecurityToken token;
            ClaimsPrincipal user;

            try
            {
                user = handler.ValidateToken(identityToken, parameters, out token);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());

                return new IdentityTokenValidationResult
                {
                    Error = $"Error validating identity token: {ex.ToString()}"
                };
            }

            return new IdentityTokenValidationResult
            {
                User = user,
                SignatureAlgorithm = algorithm
            };
        }
    }
}