using IdentityModel.Client;
using System;
using System.Text;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Infrastructure;
using System.Security.Cryptography;
using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    internal class ResponseValidator
    {
        //private static readonly ILog Logger = LogProvider.For<ResponseValidator>();

        private readonly OidcClientOptions _options;
        private TokenClient _tokenClient;

        public ResponseValidator(OidcClientOptions options)
        {
            _options = options;
        }

        public async Task<ResponseValidationResult> ValidateHybridFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            //Logger.Debug("Validate hybrid flow response");
            var result = new ResponseValidationResult();

            if (authorizeResponse.IdentityToken.IsMissing())
            {
                result.Error = "Missing identity token";
                //Logger.Error(result.Error);

                return result;
            }
            
            var validationResult = await ValidateIdentityTokenAsync(authorizeResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "Identity token validation error";
                //Logger.Error(result.Error);

                return result;
            }

            if (!ValidateNonce(state.Nonce, validationResult.User))
            {
                result.Error = "Invalid nonce";
                //Logger.Error(result.Error);

                return result;
            }

            var signingAlgorithmBits = int.Parse(validationResult.SignatureAlgorithm.Substring(2));
            if (!ValidateAuthorizationCodeHash(authorizeResponse.Code, signingAlgorithmBits, validationResult.User))
            {
                result.Error = "Invalid c_hash";
                //Logger.Error(result.Error);

                return result;
            }

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                //Logger.Error(result.Error);
                result.Error = tokenResponse.Error;
                return result;
            }

            return new ResponseValidationResult
            {
                AuthorizeResponse = authorizeResponse,
                TokenResponse = tokenResponse,
                User = validationResult.User
            };
        }


        public async Task<ResponseValidationResult> ValidateCodeFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            //Logger.Debug("Validate code flow response");
            var result = new ResponseValidationResult();

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                result.Error = tokenResponse.Error;
                return result;
            }

            if (tokenResponse.IdentityToken.IsMissing())
            {
                result.Error = "Missing identity token";
                //Logger.Error(result.Error);

                return result;
            }

            var validationResult = await ValidateIdentityTokenAsync(tokenResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "Identity token validation error";
                //Logger.Error(result.Error);

                return result;
            }

            var signingAlgorithmBits = int.Parse(validationResult.SignatureAlgorithm.Substring(2));
            if (!ValidateAccessTokenHash(tokenResponse.AccessToken, signingAlgorithmBits, validationResult.User))
            {
                result.Error = "Invalid access token hash";
                //Logger.Error(result.Error);

                return result;
            }

            return new ResponseValidationResult
            {
                AuthorizeResponse = authorizeResponse,
                TokenResponse = tokenResponse,
                User = validationResult.User
            };
        }

        private async Task<IdentityTokenValidationResult> ValidateIdentityTokenAsync(string idToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();

            //Logger.Debug("Calling identity token validator: " + _options.IdentityTokenValidator.GetType().FullName);
            var validationResult = await _options.IdentityTokenValidator.ValidateAsync(idToken, _options.ClientId, providerInfo);

            if (validationResult.Success == false)
            {
                return validationResult;
            }

            var claims = validationResult.Claims;

            //Logger.Debug("identity token validation claims:");
            //Logger.LogClaims(claims);

            // validate audience
            var audience = claims.FindFirst(JwtClaimTypes.Audience)?.Value ?? "";
            if (!string.Equals(_options.ClientId, audience, StringComparison.Ordinal))
            {
                //Logger.Error($"client id ({_options.ClientId}) does not match audience ({audience})");

                return new IdentityTokenValidationResult
                {
                    Error = "invalid audience"
                };
            }

            // validate issuer
            var issuer = claims.FindFirst(JwtClaimTypes.Issuer)?.Value ?? "";
            if (!string.Equals(providerInfo.IssuerName, issuer, StringComparison.Ordinal))
            {
                //Logger.Error($"configured issuer ({providerInfo.IssuerName}) does not match token issuer ({issuer}");

                return new IdentityTokenValidationResult
                {
                    Error = "invalid issuer"
                };
            }

            return validationResult;
        }

        private bool ValidateNonce(string nonce, ClaimsPrincipal claims)
        {
            //Logger.Debug("validate nonce");

            var tokenNonce = claims.FindFirst(JwtClaimTypes.Nonce)?.Value ?? "";
            var match = string.Equals(nonce, tokenNonce, StringComparison.Ordinal);

            if (!match)
            {
                //Logger.Error($"nonce ({nonce}) does not match nonce from token ({tokenNonce})");
            }

            //Logger.Debug("success");
            return match;
        }

        private bool ValidateAuthorizationCodeHash(string code, int signingAlgorithmBits, ClaimsPrincipal claims)
        {
            //Logger.Debug("validate authorization code hash");

            var cHash = claims.FindFirst(JwtClaimTypes.AuthorizationCodeHash)?.Value ?? "";
            if (cHash.IsMissing())
            {
                return true;
            }

            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(code));

                byte[] leftPart = new byte[16];
                Array.Copy(hash, leftPart, 16);

                var leftPartB64 = Base64Url.Encode(leftPart);
                var match = leftPartB64.Equals(cHash);

                if (!match)
                {
                    //_logger.LogError($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
                }

                return match;
            }

            //var hashAlgorithm = GetHashAlgorithm(signingAlgorithmBits);
            //if (hashAlgorithm == null)
            //{
            //    //Logger.Error("No appropriate hashing algorithm found.");
            //}

            //var codeHash = hashAlgorithm.HashData(
            //    CryptographicBuffer.CreateFromByteArray(
            //        Encoding.UTF8.GetBytes(code)));

            //byte[] codeHashArray;
            //CryptographicBuffer.CopyToByteArray(codeHash, out codeHashArray);

            //byte[] leftPart = new byte[signingAlgorithmBits / 16];
            //Array.Copy(codeHashArray, leftPart, signingAlgorithmBits / 16);

            //var leftPartB64 = Base64Url.Encode(leftPart);
            //var match = leftPartB64.Equals(cHash);

            //if (!match)
            //{
            //    //Logger.Error($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
            //}

            //Logger.Debug("success");
            //return match;
        }

        private bool ValidateAccessTokenHash(string accessToken, int signingAlgorithmBits, ClaimsPrincipal claims)
        {
            //Logger.Debug("validate authorization code hash");

            var atHash = claims.FindFirst(JwtClaimTypes.AccessTokenHash)?.Value ?? "";
            if (atHash.IsMissing())
            {
                return true;
            }

            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(accessToken));

                byte[] leftPart = new byte[16];
                Array.Copy(hash, leftPart, 16);

                var leftPartB64 = Base64Url.Encode(leftPart);
                var match = leftPartB64.Equals(atHash);

                if (!match)
                {
                    //_logger.LogError($"access token hash ({leftPartB64}) does not match at_hash from token ({atHash})");
                }

                return match;
            }

            //var hashAlgorithm = GetHashAlgorithm(signingAlgorithmBits);
            //if (hashAlgorithm == null)
            //{
            //    //Logger.Error("No appropriate hashing algorithm found.");
            //}

            //var codeHash = hashAlgorithm.HashData(
            //    CryptographicBuffer.CreateFromByteArray(
            //        Encoding.UTF8.GetBytes(accessToken)));

            //byte[] atHashArray;
            //CryptographicBuffer.CopyToByteArray(codeHash, out atHashArray);

            //byte[] leftPart = new byte[signingAlgorithmBits / 16];
            //Array.Copy(atHashArray, leftPart, signingAlgorithmBits / 16);

            //var leftPartB64 = Base64Url.Encode(leftPart);

            //var match = leftPartB64.Equals(atHash);

            //if (!match)
            //{
            //    //Logger.Error($"access token hash ({leftPartB64}) does not match at_hash from token ({atHash})");
            //}

            ////Logger.Debug("success");
            //return match;
        }

        private async Task<TokenResponse> RedeemCodeAsync(string code, AuthorizeState state)
        {
            //Logger.Debug("Redeeming authorization code");

            var client = await GetTokenClientAsync();

            var tokenResult = await client.RequestAuthorizationCodeAsync(
                code,
                state.RedirectUri,
                codeVerifier: state.CodeVerifier);

            return tokenResult;
        }


        //private IHashAlgorithmProvider GetHashAlgorithm(int signingAlgorithmBits)
        //{
        //    //Logger.Debug($"determining hash algorithm for {signingAlgorithmBits} bits");

        //    switch (signingAlgorithmBits)
        //    {
        //        case 256:
        //            //Logger.Debug("SHA256");
        //            return HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
        //        case 384:
        //            //Logger.Debug("SHA384");
        //            return HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha384);
        //        case 512:
        //            //Logger.Debug("SHA512");
        //            return HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha512);
        //        default:
        //            return null;
        //    }
        //}

        private async Task<TokenClient> GetTokenClientAsync()
        {
            if (_tokenClient == null)
            {
                _tokenClient = await TokenClientFactory.CreateAsync(_options);
            }

            return _tokenClient;
        }
    }
}