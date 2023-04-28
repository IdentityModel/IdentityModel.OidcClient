using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.DPoP
{
    public class ProofToken
    {
        private readonly JsonWebKey _key;

        private static readonly JsonWebTokenHandler Handler = new JsonWebTokenHandler
            { SetDefaultTimesOnTokenCreation = false };

        public static string CanonicalizeUrl(Uri url)
        {
            return url.Scheme + "://" + url.Host + url.AbsolutePath;
        }

        public static ProofTokenValidationResult ValidateToken(string value)
        {
            // spec:
            // all required claims per Section 4.2 are contained in the JWT,
            // the typ JOSE header parameter has the value dpop+jwt,
            // the alg JOSE header parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is acceptable per local policy,
            // the JWT signature verifies with the public key contained in the jwk JOSE header parameter,
            // the jwk JOSE header parameter does not contain a private key,
            
            var jwt = new JsonWebToken(value);
            
            var dpopJwkString = jwt.GetHeaderValue<string>(JwtClaimTypes.JsonWebKey);
            if (string.IsNullOrWhiteSpace(dpopJwkString))
            {
                throw new InvalidOperationException("JWK header is missing.");
            }

            // todo: no concept of "invalid jwk" - but spec requires well-formedness
            var signingKey = new JsonWebKey(dpopJwkString);
            if (signingKey.HasPrivateKey)
            {
                return new ProofTokenValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "JWK contains private key"
                };
            }
            
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false,
                ValidTypes = new[] { JwtClaimTypes.JwtTypes.DPoPProofToken },
                
                RequireSignedTokens = true,
                ValidAlgorithms = new[]
                {
                    OidcConstants.Algorithms.Asymmetric.ES256,
                    OidcConstants.Algorithms.Asymmetric.ES384,
                    OidcConstants.Algorithms.Asymmetric.ES512,
                    
                    OidcConstants.Algorithms.Asymmetric.PS256,
                    OidcConstants.Algorithms.Asymmetric.PS384,
                    OidcConstants.Algorithms.Asymmetric.PS512,
                    
                    OidcConstants.Algorithms.Asymmetric.RS256,
                    OidcConstants.Algorithms.Asymmetric.RS384,
                    OidcConstants.Algorithms.Asymmetric.RS512
                },
                
                IssuerSigningKey = signingKey
            };

            var result = Handler.ValidateToken(value, parameters);

            // token is valid - check for required claims
            if (result.IsValid)
            {
                if (!result.Claims.TryGetValue(JwtClaimTypes.DPoPHttpMethod, out _))
                {
                    return new ProofTokenValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "htm claim is missing"
                    };
                }
                
                if (!result.Claims.TryGetValue(JwtClaimTypes.DPoPHttpUrl, out _))
                {
                    return new ProofTokenValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "htu claim is missing"
                    };
                }
                
                if (!result.Claims.TryGetValue(JwtClaimTypes.IssuedAt, out _))
                {
                    return new ProofTokenValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "iat claim is missing"
                    };
                }
                
                if (!result.Claims.TryGetValue(JwtClaimTypes.JwtId, out _))
                {
                    return new ProofTokenValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "jti claim is missing"
                    };
                }
                
                return new ProofTokenValidationResult
                {
                    IsValid = true,
                    Payload = result.Claims,
                    JsonWebKey = signingKey
                };
            }

            return new ProofTokenValidationResult
            {
                IsValid = false,
                ErrorMessage = result.Exception.ToString()
            };
        }

        

        public static string CalculateAccessTokenHash(string accessToken)
        {
            var ascii = ASCIIEncoding.Default.GetBytes(accessToken);

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(ascii);
                return Base64Url.Encode(hash);
            }
        }
        
        public ProofToken(JsonWebKey key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));

            if (!_key.HasPrivateKey)
            {
                throw new InvalidOperationException("private key required.");
            }

            // alg: an identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS].
            // MUST NOT be none or an identifier for a symmetric algorithm (MAC).
            if (string.Equals(_key.Kty, JsonWebAlgorithmsKeyTypes.Octet))
            {
                throw new InvalidOperationException("key type must be asymmetric.");
            }

            if (string.IsNullOrWhiteSpace(_key.Alg))
            {
                throw new InvalidOperationException("algorithm must be set.");
            }
        }

        public string CreateToken(HttpRequestMessage request, string nonce = null)
        {
            var headerElements = CreateHeaderElements();
            var payload = CreatePayload(request, nonce);

            return Handler.CreateToken(payload, new SigningCredentials(_key, _key.Alg), headerElements);
        }
        
        public string CreateToken(string httpMethod, Uri httpUrl, string accessToken = null, string nonce = null)
        {
            var headerElements = CreateHeaderElements();
            var payload = CreatePayload(httpMethod, httpUrl, accessToken, nonce);

            return Handler.CreateToken(payload, new SigningCredentials(_key, _key.Alg), headerElements);
        }

        public Dictionary<string, object> CreateHeaderElements()
        {
            object jwk;

            // jwk: representing the public key chosen by the client, in JSON Web Key (JWK) [RFC7517] format,
            // as defined in Section 4.1.3 of [RFC7515]. MUST NOT contain a private key.

            if (string.Equals(_key.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve))
            {
                jwk = new
                {
                    kty = _key.Kty,
                    x = _key.X,
                    y = _key.Y,
                    crv = _key.Crv
                };
            }
            else if (string.Equals(_key.Kty, JsonWebAlgorithmsKeyTypes.RSA))
            {
                jwk = new
                {
                    kty = _key.Kty,
                    e = _key.E,
                    n = _key.N
                };
            }
            else
            {
                throw new InvalidOperationException("invalid key type.");
            }

            // typ: with value dpop+jwt, which explicitly types the DPoP proof JWT as recommended in Section 3.11 of [RFC8725].
            var additionalHeaderElements = new Dictionary<string, object>
            {
                { "typ", "dpop+jwt" },
                { "jwk", jwk }
            };

            return additionalHeaderElements;
        }
        
        public string CreatePayload(HttpRequestMessage request, string nonce = null)
        {
            string accessToken = null;
            
            var header = request.Headers.Authorization;
            if (header is { Scheme: OidcConstants.HttpHeaders.DPoP } && !string.IsNullOrWhiteSpace(header.Parameter))
            {
                accessToken = header.Parameter;
            }

            return CreatePayload(request.Method.Method, request.RequestUri, accessToken, nonce);
        }

        public string CreatePayload(string httpMethod, Uri httpUrl, string accessToken = null, string nonce = null)
        {
            // jti: Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 UUID string according to [RFC4122]. The jti can be used by the server for replay detection and prevention, see Section 11.1.
            // htm: The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.
            // htu: The HTTP target URI (Section 7.1 of [RFC9110]), without query and fragment parts, of the request to which the JWT is attached.
            // iat: Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).
            
            var payload = new Dictionary<string, object>()
            {
                { JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId() },
                { JwtClaimTypes.DPoPHttpMethod, httpMethod },
                { JwtClaimTypes.DPoPHttpUrl, CanonicalizeUrl(httpUrl) },
                { JwtClaimTypes.IssuedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            // nonce: A recent nonce provided via the DPoP-Nonce HTTP header.
            if (nonce != null)
            {
                payload.Add(JwtClaimTypes.Nonce, nonce);
            }

            // ath: hash of the access token.
            // The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                payload.Add(JwtClaimTypes.DPoPAccessTokenHash, CalculateAccessTokenHash(accessToken));
            }
            
            return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}