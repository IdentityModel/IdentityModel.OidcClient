using IdentityModel.Client;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    internal class ResponseProcessor
    {
        private readonly OidcClientOptions _options;
        private TokenClient _tokenClient;
        private ILogger<ResponseProcessor> _logger;

        public ResponseProcessor(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<ResponseProcessor>();
        }

        public async Task<ResponseValidationResult> ValidateHybridFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            _logger.LogTrace("ValidateHybridFlowResponseAsync");

            var result = new ResponseValidationResult();

            //////////////////////////////////////////////////////
            // validate front-channel response
            //////////////////////////////////////////////////////

            // id_token must be present
            if (authorizeResponse.IdentityToken.IsMissing())
            {
                result.Error = "Missing identity token";
                _logger.LogError(result.Error);

                return result;
            }

            // id_token must be valid
            var validationResult = await ValidateIdentityTokenAsync(authorizeResponse.IdentityToken);
            if (validationResult.IsError)
            {
                result.Error = validationResult.Error ?? "Identity token validation error";
                _logger.LogError(result.Error);

                return result;
            }

            // nonce must be valid
            if (!ValidateNonce(state.Nonce, validationResult.User))
            {
                result.Error = "Invalid nonce";
                _logger.LogError(result.Error);

                return result;
            }

            // todo: policy
            // if c_hash is present, it must be valid
            var signingAlgorithmBits = int.Parse(validationResult.SignatureAlgorithm.Substring(2));
            if (!ValidateAuthorizationCodeHash(authorizeResponse.Code, signingAlgorithmBits, validationResult.User))
            {
                result.Error = "Invalid c_hash";
                _logger.LogError(result.Error);

                return result;
            }

            //////////////////////////////////////////////////////
            // process back-channel response
            //////////////////////////////////////////////////////

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                _logger.LogError(result.Error);
                result.Error = tokenResponse.Error;

                return result;
            }

            // validate token response
            var tokenResponseValidationResult = await ValidateTokenResponse(tokenResponse);
            if (tokenResponseValidationResult.IsError)
            {
                result.Error = tokenResponseValidationResult.Error;
                return result;
            }

            return new ResponseValidationResult
            {
                AuthorizeResponse = authorizeResponse,
                TokenResponse = tokenResponse,
                
                //todo
                //User = tokenResponseValidationResult
            };
        }

        public async Task<ResponseValidationResult> ValidateCodeFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            _logger.LogTrace("ValidateCodeFlowResponseAsync");

            var result = new ResponseValidationResult();

            //////////////////////////////////////////////////////
            // validate front-channel response
            //////////////////////////////////////////////////////

            // code must be present
            if (authorizeResponse.Code.IsMissing())
            {
                result.Error = "code is missing";
                _logger.LogError(result.Error);

                return result;
            }

            if (!string.Equals(authorizeResponse.State, state.State, StringComparison.Ordinal))
            {
                result.Error = "invalid state";
                _logger.LogError(result.Error);

                return result;
            }

            //////////////////////////////////////////////////////
            // process back-channel response
            //////////////////////////////////////////////////////

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                // todo: logging?
                result.Error = tokenResponse.Error;
                return result;
            }

            // validate token response
            var tokenResponseValidationResult = await ValidateTokenResponse(tokenResponse);
            if (tokenResponseValidationResult.IsError)
            {
                result.Error = tokenResponseValidationResult.Error;
                return result;
            }

            return new ResponseValidationResult
            {
                AuthorizeResponse = authorizeResponse,
                TokenResponse = tokenResponse,

                //todo
                //Claims = tokenResponseValidationResult.IdentityTokenValidationResult.Claims
            };
        }

        public async Task<TokenResponseValidationResult> ValidateTokenResponse(TokenResponse response, bool requireIdentityToken = true)
        {
            _logger.LogTrace("ValidateTokenResponse");

            var result = new TokenResponseValidationResult();

            // token response must contain an access token
            if (response.AccessToken.IsMissing())
            {
                result.Error = "access token is missing on token response";
                _logger.LogError(result.Error);

                return result;
            }

            if (requireIdentityToken)
            {
                // token response must contain an identity token (openid scope is mandatory)
                if (response.IdentityToken.IsMissing())
                {
                    result.Error = "identity token is missing on token response";
                    _logger.LogError(result.Error);

                    return result;
                }
            }

            if (response.IdentityToken.IsPresent())
            {
                // if identity token is present, it must be valid
                var validationResult = await ValidateIdentityTokenAsync(response.IdentityToken);
                if (validationResult.IsError)
                {
                    result.Error = validationResult.Error ?? "Identity token validation error";
                    _logger.LogError(result.Error);

                    return result;
                }

                // if at_hash is present, it must be valid
                var signingAlgorithmBits = int.Parse(validationResult.SignatureAlgorithm.Substring(2));
                if (!ValidateAccessTokenHash(response.AccessToken, signingAlgorithmBits, validationResult.User))
                {
                    result.Error = "Invalid access token hash";
                    _logger.LogError(result.Error);

                    return result;
                }

                return new TokenResponseValidationResult
                {
                    IdentityTokenValidationResult = validationResult
                };
            }

            return new TokenResponseValidationResult();
        }

        private async Task<IdentityTokenValidationResult> ValidateIdentityTokenAsync(string idToken)
        {
            _logger.LogDebug("Calling identity token validator: " + _options.IdentityTokenValidator.GetType().FullName);

            var validationResult = await _options.IdentityTokenValidator.ValidateAsync(idToken, _options.ClientId, _options.ProviderInformation);

            if (validationResult.IsError)
            {
                return validationResult;
            }

            var user = validationResult.User;

            //Logger.Debug("identity token validation claims:");
            //Logger.LogClaims(claims);

            // validate audience
            var audience = user.FindFirst(JwtClaimTypes.Audience)?.Value ?? "";
            if (!string.Equals(_options.ClientId, audience, StringComparison.Ordinal))
            {
                _logger.LogError($"client id ({_options.ClientId}) does not match audience ({audience})");

                return new IdentityTokenValidationResult
                {
                    Error = "invalid audience"
                };
            }

            // validate issuer
            var issuer = user.FindFirst(JwtClaimTypes.Issuer)?.Value ?? "";
            if (!string.Equals(_options.ProviderInformation.IssuerName, issuer, StringComparison.Ordinal))
            {
                _logger.LogError($"configured issuer ({_options.ProviderInformation.IssuerName}) does not match token issuer ({issuer}");

                return new IdentityTokenValidationResult
                {
                    Error = "invalid issuer"
                };
            }

            return validationResult;
        }

        private bool ValidateNonce(string nonce, ClaimsPrincipal user)
        {
            _logger.LogTrace("ValidateNonce");

            var tokenNonce = user.FindFirst(JwtClaimTypes.Nonce)?.Value ?? "";
            var match = string.Equals(nonce, tokenNonce, StringComparison.Ordinal);

            if (!match)
            {
                _logger.LogError($"nonce ({nonce}) does not match nonce from token ({tokenNonce})");
            }

            return match;
        }

        private bool ValidateAuthorizationCodeHash(string code, int signingAlgorithmBits, ClaimsPrincipal claims)
        {
            _logger.LogTrace("ValidateAuthorizationCodeHash");

            var cHash = claims.FindFirst(JwtClaimTypes.AuthorizationCodeHash)?.Value ?? "";
            if (cHash.IsMissing())
            {
                return true;
            }

            var hashAlgorithm = GetHashAlgorithm(signingAlgorithmBits);
            if (hashAlgorithm == null)
            {
                _logger.LogError("No appropriate hashing algorithm found.");
            }

            using (hashAlgorithm)
            {
                var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(code));

                byte[] leftPart = new byte[signingAlgorithmBits / 16];
                Array.Copy(hash, leftPart, signingAlgorithmBits / 16);

                var leftPartB64 = Base64Url.Encode(leftPart);
                var match = leftPartB64.Equals(cHash);

                if (!match)
                {
                    _logger.LogError($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
                }

                return match;
            }
        }

        private bool ValidateAccessTokenHash(string accessToken, int signingAlgorithmBits, ClaimsPrincipal user)
        {
            _logger.LogTrace("ValidateAccessTokenHash");

            var atHash = user.FindFirst(JwtClaimTypes.AccessTokenHash)?.Value ?? "";
            if (atHash.IsMissing())
            {
                return true;
            }

            var hashAlgorithm = GetHashAlgorithm(signingAlgorithmBits);
            if (hashAlgorithm == null)
            {
                _logger.LogError("No appropriate hashing algorithm found.");
            }

            using (hashAlgorithm)
            {
                var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(atHash));

                byte[] leftPart = new byte[signingAlgorithmBits / 16];
                Array.Copy(hash, leftPart, signingAlgorithmBits / 16);

                var leftPartB64 = Base64Url.Encode(leftPart);
                var match = leftPartB64.Equals(atHash);

                if (!match)
                {
                    _logger.LogError($"code hash ({leftPartB64}) does not match c_hash from token ({atHash})");
                }

                return match;
            }
        }

        private async Task<TokenResponse> RedeemCodeAsync(string code, AuthorizeState state)
        {
            _logger.LogTrace("RedeemCodeAsync");

            var client = GetTokenClient();

            var tokenResult = await client.RequestAuthorizationCodeAsync(
                code,
                state.RedirectUri,
                codeVerifier: state.CodeVerifier);

            return tokenResult;
        }


        private HashAlgorithm GetHashAlgorithm(int signingAlgorithmBits)
        {
            _logger.LogDebug($"determining hash algorithm for {signingAlgorithmBits} bits");

            switch (signingAlgorithmBits)
            {
                case 256:
                    _logger.LogDebug("SHA256");
                    return SHA256.Create();
                case 384:
                    _logger.LogDebug("SHA384");
                    return SHA384.Create();
                case 512:
                    _logger.LogDebug("SHA512");
                    return SHA512.Create();
                default:
                    return null;
            }
        }

        private TokenClient GetTokenClient()
        {
            if (_tokenClient == null)
            {
                _tokenClient = TokenClientFactory.Create(_options);
            }

            return _tokenClient;
        }
    }
}
