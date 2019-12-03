// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    internal class ResponseProcessor
    {
        private readonly OidcClientOptions _options;
        private ILogger<ResponseProcessor> _logger;
        private readonly IdentityTokenValidator _tokenValidator;
        private readonly CryptoHelper _crypto;
        private readonly Func<CancellationToken, Task> _refreshKeysAsync;

        public ResponseProcessor(OidcClientOptions options, Func<CancellationToken, Task> refreshKeysAsync)
        {
            _options = options;
            _refreshKeysAsync = refreshKeysAsync;
            _logger = options.LoggerFactory.CreateLogger<ResponseProcessor>();

            _tokenValidator = new IdentityTokenValidator(options, refreshKeysAsync);
            _crypto = new CryptoHelper(options);
        }

        public async Task<ResponseValidationResult> ProcessResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state,
            IDictionary<string, string> extraParameters, CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("ProcessResponseAsync");

            //////////////////////////////////////////////////////
            // validate common front-channel parameters
            //////////////////////////////////////////////////////

            if (string.IsNullOrEmpty(authorizeResponse.Code))
            {
                return new ResponseValidationResult("Missing authorization code.");
            }

            if (string.IsNullOrEmpty(authorizeResponse.State))
            {
                return new ResponseValidationResult("Missing state.");
            }

            if (!string.Equals(state.State, authorizeResponse.State, StringComparison.Ordinal))
            {
                return new ResponseValidationResult("Invalid state.");
            }

            return await ProcessCodeFlowResponseAsync(authorizeResponse, state, extraParameters, cancellationToken);
        }

        private async Task<ResponseValidationResult> ProcessCodeFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state, IDictionary<string, string> extraParameters, CancellationToken cancellationToken)
        {
            _logger.LogTrace("ProcessCodeFlowResponseAsync");

            //////////////////////////////////////////////////////
            // process back-channel response
            //////////////////////////////////////////////////////

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state, extraParameters, cancellationToken);
            if (tokenResponse.IsError)
            {
                return new ResponseValidationResult($"Error redeeming code: {tokenResponse.Error ?? "no error code"} / {tokenResponse.ErrorDescription ?? "no description"}");
            }

            // validate token response
            var tokenResponseValidationResult = await ValidateTokenResponseAsync(tokenResponse, state, requireIdentityToken:false, cancellationToken: cancellationToken);
            if (tokenResponseValidationResult.IsError)
            {
                return new ResponseValidationResult($"Error validating token response: {tokenResponseValidationResult.Error}");
            }

            return new ResponseValidationResult
            {
                AuthorizeResponse = authorizeResponse,
                TokenResponse = tokenResponse,
                User = tokenResponseValidationResult?.IdentityTokenValidationResult?.User ?? Principal.Create(_options.Authority)
            };
        }

        internal async Task<TokenResponseValidationResult> ValidateTokenResponseAsync(TokenResponse response, AuthorizeState state, bool requireIdentityToken, CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("ValidateTokenResponse");

            // token response must contain an access token
            if (response.AccessToken.IsMissing())
            {
                return new TokenResponseValidationResult("Access token is missing on token response.");
            }

            if (requireIdentityToken)
            {
                // token response must contain an identity token (openid scope is mandatory)
                if (response.IdentityToken.IsMissing())
                {
                    return new TokenResponseValidationResult("Identity token is missing on token response.");
                }
            }

            if (response.IdentityToken.IsPresent())
            {
                // if identity token is present, it must be valid
                var validationResult = await _tokenValidator.ValidateAsync(response.IdentityToken, cancellationToken);
                if (validationResult.IsError)
                {
                    return new TokenResponseValidationResult(validationResult.Error ?? "Identity token validation error");
                }

                // validate nonce
                if (state != null)
                {
                    if (!ValidateNonce(state.Nonce, validationResult.User))
                    {
                        return new TokenResponseValidationResult("Invalid nonce.");
                    }
                }

                // validate at_hash
                var atHash = validationResult.User.FindFirst(JwtClaimTypes.AccessTokenHash);
                if (atHash == null)
                {
                    if (_options.Policy.RequireAccessTokenHash)
                    {
                        return new TokenResponseValidationResult("at_hash is missing.");
                    }
                }
                else
                {
                    if (!_crypto.ValidateHash(response.AccessToken, atHash.Value, validationResult.SignatureAlgorithm))
                    {
                        return new TokenResponseValidationResult("Invalid access token hash.");
                    }
                }

                return new TokenResponseValidationResult(validationResult);
            }

            return new TokenResponseValidationResult((IdentityTokenValidationResult)null);
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

        private async Task<TokenResponse> RedeemCodeAsync(string code, AuthorizeState state, IDictionary<string, string> extraParameters, CancellationToken cancellationToken)
        {
            _logger.LogTrace("RedeemCodeAsync");

            var client = _options.CreateClient();
            var tokenResult = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = _options.ProviderInformation.TokenEndpoint,

                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                ClientCredentialStyle = _options.TokenClientCredentialStyle,

                Code = code,
                RedirectUri = state.RedirectUri,
                CodeVerifier = state.CodeVerifier,
                Parameters = extraParameters ?? new Dictionary<string, string>()
            }, cancellationToken).ConfigureAwait(false);

            return tokenResult;
        }
    }
}