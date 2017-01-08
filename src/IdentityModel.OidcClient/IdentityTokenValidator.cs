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
    public class IdentityTokenValidator
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;

        public IdentityTokenValidator(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<IdentityTokenValidator>();
        }

        public IdentityTokenValidationResult Validate(string identityToken)
        {
            var keys = new List<SecurityKey>();
            foreach (var webKey in _options.ProviderInformation.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                key.KeyId = webKey.Kid;

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _options.ProviderInformation.IssuerName,
                ValidAudience = _options.ClientId,
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,

                ClockSkew = _options.ClockSkew
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

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
                    Error = ex.ToString()
                };
            }

            var jwt = token as JwtSecurityToken;
            var algorithm = jwt.Header.Alg;

            if (!_options.Policy.SupportedAlgorithms.Contains(algorithm))
            {
                return new IdentityTokenValidationResult
                {
                    Error = $"Identity token uses unsupported algorithm: {algorithm}"
                };
            };

            return new IdentityTokenValidationResult
            {
                User = user,
                SignatureAlgorithm = algorithm
            };
        }
    }
}