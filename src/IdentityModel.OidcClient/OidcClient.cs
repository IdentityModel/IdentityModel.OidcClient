// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using IdentityModel.OidcClient.Infrastructure;
using System.Security.Claims;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// OpenID Connect client
    /// </summary>
    public class OidcClient
    {
        //private static readonly ILog Logger = LogProvider.For<OidcClient>();

        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientOptions _options;
        private readonly ResponseValidator _validator;

        /// <summary>
        /// Gets the options.
        /// </summary>
        /// <value>
        /// The options.
        /// </value>
        public OidcClientOptions Options
        {
            get { return _options; }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OidcClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public OidcClient(OidcClientOptions options)
        {
            _authorizeClient = new AuthorizeClient(options);
            _validator = new ResponseValidator(options);

            _options = options;
        }

        /// <summary>
        /// Starts an authentication request.
        /// </summary>
        /// <param name="trySilent">if set to <c>true</c> a silent login attempt is made.</param>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns></returns>
        public async Task<LoginResult> LoginAsync(bool trySilent = false, object extraParameters = null)
        {
            //Logger.Debug("LoginAsync");

            var authorizeResult = await _authorizeClient.AuthorizeAsync(trySilent, extraParameters);

            if (!authorizeResult.Success)
            {
                return new LoginResult(authorizeResult.Error);
            }

            return await ValidateResponseAsync(authorizeResult.Data, authorizeResult.State);
        }

        /// <summary>
        /// Prepares an authentication request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>An authorize state object that can be later used to validate the response</returns>
        public async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            //Logger.Debug("PrepareLoginAsync");

            return await _authorizeClient.PrepareAuthorizeAsync(extraParameters);
        }

        /// <summary>
        /// Starts and end session request.
        /// </summary>
        /// <param name="identityToken">An identity token to send as a hint.</param>
        /// <param name="trySilent">if set to <c>true</c> a silent end session attempt is made.</param>
        /// <returns></returns>
        public Task LogoutAsync(string identityToken = null, bool trySilent = true)
        {
            return _authorizeClient.EndSessionAsync(identityToken, trySilent);
        }

        /// <summary>
        /// Validates the response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <returns>Result of the login response validation</returns>
        /// <exception cref="System.InvalidOperationException">Invalid authentication style</exception>
        public async Task<LoginResult> ValidateResponseAsync(string data, AuthorizeState state)
        {
            //Logger.Debug("Validate authorize response");
            
            var response = new AuthorizeResponse(data);

            if (response.IsError)
            {
                //Logger.Error(response.Error);

                return new LoginResult(response.Error);
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                var error = "Missing authorization code";
                //Logger.Error(error);

                return new LoginResult(error);
            }

            if (string.IsNullOrEmpty(response.State))
            {
                var error = "Missing state";
                //Logger.Error(error);

                return new LoginResult(error);
            }

            if (!string.Equals(state.State, response.State, StringComparison.Ordinal))
            {
                var error = "Invalid state";
                //Logger.Error(error);

                return new LoginResult(error);
            }

            ResponseValidationResult validationResult = null;
            if (_options.Style == OidcClientOptions.AuthenticationStyle.AuthorizationCode)
            {
                validationResult = await _validator.ValidateCodeFlowResponseAsync(response, state);
            }
            else if (_options.Style == OidcClientOptions.AuthenticationStyle.Hybrid)
            {
                validationResult = await _validator.ValidateHybridFlowResponseAsync(response, state);
            }
            else
            {
                throw new InvalidOperationException("Invalid authentication style");
            }

            if (!validationResult.Success)
            {
                //Logger.Error("Error validating response: " + validationResult.Error);

                return new LoginResult(validationResult.Error);
            }

            return await ProcessClaimsAsync(validationResult);
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            var providerInfo = await _options.GetProviderInformationAsync();

            if (accessToken.IsMissing()) throw new ArgumentNullException(nameof(accessToken));
            if (providerInfo.UserInfoEndpoint.IsMissing()) throw new InvalidOperationException("No userinfo endpoint specified");
            
            var handler = _options.BackchannelHandler ?? new HttpClientHandler();

            var userInfoClient = new UserInfoClient(providerInfo.UserInfoEndpoint, handler);
            userInfoClient.Timeout = _options.BackchannelTimeout;

            var userInfoResponse = await userInfoClient.GetAsync(accessToken);
            if (userInfoResponse.IsError)
            {
                return new UserInfoResult
                {
                    Error = userInfoResponse.Error
                };
            }

            return new UserInfoResult
            {
                Claims = userInfoResponse.Claims
            };
        }

        /// <summary>
        /// Startes a refresh token requeszt.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>A refresh token result</returns>
        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken)
        {
            var client = await TokenClientFactory.CreateAsync(_options);
            var response = await client.RequestRefreshTokenAsync(refreshToken);

            if (response.IsError)
            {
                return new RefreshTokenResult
                {
                    Error = response.Error
                };
            }
            else
            {
                return new RefreshTokenResult
                {
                    AccessToken = response.AccessToken,
                    RefreshToken = response.RefreshToken,
                    ExpiresIn = (int)response.ExpiresIn
                };
            }
        }

        private async Task<LoginResult> ProcessClaimsAsync(ResponseValidationResult result)
        {
            //Logger.Debug("Processing claims");

            // get profile if enabled
            if (_options.LoadProfile)
            {
                //Logger.Debug("load profile");

                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);

                if (!userInfoResult.Success)
                {
                    return new LoginResult(userInfoResult.Error);
                }

                //Logger.Debug("profile claims:");
                //Logger.LogClaims(userInfoResult.Claims);

                var primaryClaimTypes = result.User.Claims.Select(c => c.Type).Distinct();
                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
                {
                    result.Claims.Add(claim);
                }
            }
            else
            {
                //Logger.Debug("don't load profile");
            }

            // success
            var loginResult = new LoginResult
            {
                User = Principal.Create("oidc", FilterClaims(result.Claims)),
                AccessToken = result.TokenResponse.AccessToken,
                RefreshToken = result.TokenResponse.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
                IdentityToken = result.TokenResponse.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(result.TokenResponse.RefreshToken))
            {
                var providerInfo = await _options.GetProviderInformationAsync();

                loginResult.RefreshTokenHandler = new RefreshTokenHandler(
                    await TokenClientFactory.CreateAsync(_options),
                    result.TokenResponse.RefreshToken,
                    result.TokenResponse.AccessToken);
            }

            return loginResult;
        }
        
        private IEnumerable<Claim> FilterClaims(IEnumerable<Claim> claims)
        {
            //Logger.Debug("filtering claims");

            if (_options.FilterClaims)
            {
                claims = claims.Where(c => !_options.FilteredClaims.Contains(c.Type));
            }

            //Logger.Debug("filtered claims:");
            //Logger.LogClaims(claims);

            return claims;
        }
    }
}