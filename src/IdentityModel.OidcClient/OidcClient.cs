// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class OidcClient
    {
        //private static readonly ILog Logger = LogProvider.For<OidcClient>();

        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientOptions _options;

        public OidcClient(OidcClientOptions options)
        {
            _authorizeClient = new AuthorizeClient(options);
            _options = options;
        }

        public OidcClientOptions Options
        {
            get { return _options; }
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false, object extraParameters = null)
        {
            //Logger.Debug("LoginAsync");

            var authorizeResult = await _authorizeClient.AuthorizeAsync(trySilent, extraParameters);

            if (!authorizeResult.Success)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = authorizeResult.Error
                };
            }

            return await ValidateResponseAsync(authorizeResult.Data, authorizeResult.State);
        }

        public async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            //Logger.Debug("PrepareLoginAsync");

            return await _authorizeClient.PrepareAuthorizeAsync(extraParameters);
        }

        public Task LogoutAsync(string identityToken = null, bool trySilent = true)
        {
            return _authorizeClient.EndSessionAsync(identityToken, trySilent);
        }

        public async Task<LoginResult> ValidateResponseAsync(string data, AuthorizeState state)
        {
            //Logger.Debug("ValidateResponseAsync");

            var result = new LoginResult { Success = false };

            var response = new AuthorizeResponse(data);

            if (response.IsError)
            {
                result.Error = response.Error;
                //Logger.Error(result.Error);

                return result;
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                result.Error = "missing authorization code";
                //Logger.Error(result.Error);

                return result;
            }

            if (string.IsNullOrEmpty(response.State))
            {
                result.Error = "missing state";
                //Logger.Error(result.Error);

                return result;
            }

            if (!string.Equals(state.State, response.State, StringComparison.Ordinal))
            {
                result.Error = "invalid state";
                //Logger.Error(result.Error);

                return result;
            }

            if (_options.Style == OidcClientOptions.AuthenticationStyle.AuthorizationCode)
            {
                return await ValidateCodeFlowResponseAsync(response, state);
            }
            else if (_options.Style == OidcClientOptions.AuthenticationStyle.Hybrid)
            {
                return await ValidateHybridFlowResponseAsync(response, state);
            }

            throw new InvalidOperationException("Invalid authentication style");
        }

        private async Task<LoginResult> ValidateHybridFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            //Logger.Debug("ValidateHybridFlowResponse");

            var result = new LoginResult { Success = false };

            if (string.IsNullOrEmpty(authorizeResponse.IdentityToken))
            {
                result.Error = "missing identity token";
                //Logger.Error(result.Error);

                return result;
            }

            var validationResult = await ValidateIdentityTokenAsync(authorizeResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "identity token validation error";
                //Logger.Error(result.Error);

                return result;
            }

            if (!ValidateNonce(state.Nonce, validationResult.User))
            {
                result.Error = "invalid nonce";
                //Logger.Error(result.Error);

                return result;
            }

            if (!ValidateAuthorizationCodeHash(authorizeResponse.Code, validationResult.User))
            {
                result.Error = "invalid c_hash";
                //Logger.Error(result.Error);

                return result;
            }

            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = tokenResponse.Error
                };
            }

            return await ProcessClaimsAsync(authorizeResponse, tokenResponse, validationResult.User);
        }

        
        private async Task<LoginResult> ValidateCodeFlowResponseAsync(AuthorizeResponse authorizeResponse, AuthorizeState state)
        {
            //Logger.Debug("ValidateCodeFlowResponse");

            var result = new LoginResult { Success = false };
            
            // redeem code for tokens
            var tokenResponse = await RedeemCodeAsync(authorizeResponse.Code, state);
            if (tokenResponse.IsError)
            {
                result.Error = tokenResponse.Error;
                return result;
            }

            if (tokenResponse.IdentityToken.IsMissing())
            {
                result.Error = "missing identity token";
                //Logger.Error(result.Error);

                return result;
            }

            var validationResult = await ValidateIdentityTokenAsync(tokenResponse.IdentityToken);
            if (!validationResult.Success)
            {
                result.Error = validationResult.Error ?? "identity token validation error";
                //Logger.Error(result.Error);

                return result;
            }

            if (!ValidateAccessTokenHash(tokenResponse.AccessToken, validationResult.User))
            {
                result.Error = "invalid access token hash";
                //Logger.Error(result.Error);

                return result;
            }

            return await ProcessClaimsAsync(authorizeResponse, tokenResponse, validationResult.User);
        }

        private async Task<LoginResult> ProcessClaimsAsync(AuthorizeResponse response, TokenResponse tokenResult, ClaimsPrincipal user)
        {
            //Logger.Debug("ProcessClaimsAsync");

            // get profile if enabled
            if (_options.LoadProfile)
            {
                //Logger.Debug("load profile");

                var userInfoResult = await GetUserInfoAsync(tokenResult.AccessToken);

                if (userInfoResult.IsError)
                {
                    return new LoginResult
                    {
                        Success = false,
                        Error = userInfoResult.Error
                    };
                }

                //Logger.Debug("profile claims:");
                //Logger.LogClaims(userInfoResult.Claims);

                var primaryClaimTypes = user.Claims.Select(c => c.Type).Distinct();
                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
                {
                    user.Identities.First().AddClaim(claim);
                }

                //Logger.LogClaims(claims);
            }
            else
            {
                //Logger.Debug("don't load profile");
                //Logger.LogClaims(claims);
            }

            // success
            var loginResult = new LoginResult
            {
                Success = true,
                User = FilterClaims(user),
                AccessToken = tokenResult.AccessToken,
                RefreshToken = tokenResult.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(tokenResult.ExpiresIn),
                IdentityToken = tokenResult.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(tokenResult.RefreshToken))
            {
                var providerInfo = await _options.GetDiscoveryDocument();

                loginResult.Handler = new RefreshTokenHandler(
                    providerInfo.TokenEndpoint,
                    _options.ClientId,
                    _options.ClientSecret,
                    tokenResult.RefreshToken,
                    tokenResult.AccessToken);
            }

            return loginResult;
        }


        private async Task<IdentityTokenValidationResult> ValidateIdentityTokenAsync(string idToken)
        {
            var providerInfo = await _options.GetDiscoveryDocument();

            //Logger.Debug("Calling identity token validator: " + _options.IdentityTokenValidator.GetType().FullName);
            var validationResult = await _options.IdentityTokenValidator.ValidateAsync(idToken, _options.ClientId, providerInfo);

            if (validationResult.Success == false)
            {
                return validationResult;
            }

            var user = validationResult.User;

            //Logger.Debug("identity token validation claims:");
            //Logger.LogClaims(claims);
            
            // validate audience
            var audience = user.FindFirst(JwtClaimTypes.Audience)?.Value ?? "";
            if (!string.Equals(_options.ClientId, audience))
            {
                //Logger.Error($"client id ({_options.ClientId}) does not match audience ({audience})");

                return new IdentityTokenValidationResult
                {
                    Success = false,
                    Error = "invalid audience"
                };
            }

            // validate issuer
            var issuer = user.FindFirst(JwtClaimTypes.Issuer)?.Value ?? "";
            if (!string.Equals(providerInfo.TryGetString(OidcConstants.Discovery.Issuer), issuer))
            {
                //Logger.Error($"configured issuer ({providerInfo.IssuerName}) does not match token issuer ({issuer}");

                return new IdentityTokenValidationResult
                {
                    Success = false,
                    Error = "invalid issuer"
                };
            }

            return validationResult;
        }

        private bool ValidateNonce(string nonce, ClaimsPrincipal user)
        {
            //Logger.Debug("validate nonce");

            var tokenNonce = user.FindFirst(JwtClaimTypes.Nonce)?.Value ?? "";
            var match = string.Equals(nonce, tokenNonce, StringComparison.Ordinal);

            if (!match)
            {
                //Logger.Error($"nonce ({nonce}) does not match nonce from token ({tokenNonce})");
            }

            return match;
        }

        private bool ValidateAuthorizationCodeHash(string code, ClaimsPrincipal user)
        {
            //Logger.Debug("validate authorization code hash");

            var cHash = user.FindFirst(JwtClaimTypes.AuthorizationCodeHash)?.Value ?? "";
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
                    //Logger.Error($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
                }

                return match;
            }
        }

        private bool ValidateAccessTokenHash(string accessToken, ClaimsPrincipal user)
        {
            //Logger.Debug("validate authorization code hash");

            var atHash = user.FindFirst(JwtClaimTypes.AccessTokenHash)?.Value ?? "";
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
                    //Logger.Error($"code hash ({leftPartB64}) does not match c_hash from token ({cHash})");
                }

                return match;
            }
        }

        private async Task<TokenResponse> RedeemCodeAsync(string code, AuthorizeState state)
        {
            var endpoint = (await _options.GetDiscoveryDocument()).TokenEndpoint;

            TokenClient tokenClient;
            if (_options.ClientSecret.IsMissing())
            {
                tokenClient = new TokenClient(endpoint, _options.ClientId, AuthenticationStyle.PostValues);
            }
            else
            {
                tokenClient = new TokenClient(endpoint, _options.ClientId, _options.ClientSecret);
            }
            
            var tokenResult = await tokenClient.RequestAuthorizationCodeAsync(
                code,
                state.RedirectUri,
                codeVerifier: state.CodeVerifier);

            return tokenResult;
        }

        public async Task<UserInfoResponse> GetUserInfoAsync(string accessToken)
        {
            var providerInfo = await _options.GetDiscoveryDocument();

            var userInfoClient = new UserInfoClient(providerInfo.UserInfoEndpoint);
            return await userInfoClient.GetAsync(accessToken);
        }

        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
        {
            var providerInfo = await _options.GetDiscoveryDocument();

            var tokenClient = new TokenClient(
                providerInfo.TokenEndpoint,
                _options.ClientId,
                _options.ClientSecret);

            return await tokenClient.RequestRefreshTokenAsync(refreshToken);
        }

        private ClaimsPrincipal FilterClaims(ClaimsPrincipal user)
        {
            //Logger.Debug("filtering claims");

            var claims = new List<Claim>();
            if (_options.FilterClaims)
            {
                claims = user.Claims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToList();
            }

            //Logger.Debug("filtered claims:");
            //Logger.LogClaims(claims);

            return new ClaimsPrincipal(new ClaimsIdentity(claims, user.Identity.AuthenticationType, user.Identities.First().NameClaimType, user.Identities.First().RoleClaimType));
        }
    }
}