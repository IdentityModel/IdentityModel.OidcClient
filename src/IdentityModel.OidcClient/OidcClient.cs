// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Infrastructure;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using IdentityModel.OidcClient.Results;
using IdentityModel.OidcClient.Browser;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// OpenID Connect client
    /// </summary>
    public class OidcClient
    {
        private readonly OidcClientOptions _options;
        private readonly ILogger _logger;
        private readonly AuthorizeClient _authorizeClient;

        private readonly bool useDiscovery;
        private readonly ResponseProcessor _processor;

        public OidcClientOptions Options
        {
            get { return _options; }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OidcClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public OidcClient(OidcClientOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ProviderInformation == null)
            {
                if (options.Authority.IsMissing()) throw new ArgumentException("No authority specified", nameof(_options.Authority));
                useDiscovery = true;
            }

            _options = options;
            _logger = options.LoggerFactory.CreateLogger<OidcClient>();
            _authorizeClient = new AuthorizeClient(options);
            _processor = new ResponseProcessor(options);
        }

        public async Task<LoginResult> LoginAsync(DisplayMode displayMode = DisplayMode.Visible, int timeout = 300, object extraParameters = null)
        {
            _logger.LogTrace("LoginAsync");

            await EnsureConfiguration();
            var authorizeResult = await _authorizeClient.AuthorizeAsync(displayMode, timeout, extraParameters);

            if (authorizeResult.IsError)
            {
                return new LoginResult(authorizeResult.Error);
            }

            return await ProcessResponseAsync(authorizeResult.Data, authorizeResult.State);
        }

        /// <summary>
        /// Prepares the login request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>State for initiating the authorize request and processing the response</returns>
        public async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            _logger.LogTrace("PrepareLoginAsync");

            await EnsureConfiguration();
            return _authorizeClient.CreateAuthorizeState(extraParameters);
        }

        /// <summary>
        /// Processes the authorize response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <returns>Result of the login response validation</returns>
        public async Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state)
        {
            _logger.LogTrace("ProcessResponseAsync");

            var authorizeResponse = new AuthorizeResponse(data);

            if (authorizeResponse.IsError)
            {
                _logger.LogError(authorizeResponse.Error);
                return new LoginResult(authorizeResponse.Error);
            }

            var result = await _processor.ProcessResponseAsync(authorizeResponse, state);
            if (result.IsError)
            {
                _logger.LogError("Error validating response: " + result.Error);
                return new LoginResult(result.Error);
            }

            var userInfoClaims = Enumerable.Empty<Claim>();
            if (_options.LoadProfile)
            {
                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);
                if (userInfoResult.IsError)
                {
                    return new LoginResult($"Error contacting userinfo endpoint: {userInfoResult.Error}");
                }

                userInfoClaims = userInfoResult.Claims;

                var userInfoSub = userInfoClaims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
                if (userInfoSub == null)
                {
                    var error = "sub claim is missing from userinfo endpoint";

                    _logger.LogError(error);
                    return new LoginResult(error);
                }

                if (!string.Equals(userInfoSub.Value, result.User.FindFirst(JwtClaimTypes.Subject).Value))
                {
                    var error = "sub claim from userinfo endpoint is different than sub claim from identity token.";

                    _logger.LogError(error);
                    return new LoginResult(error);
                }
            }

            var user = ProcessClaims(result.User, userInfoClaims);

            var loginResult = new LoginResult
            {
                User = user,
                AccessToken = result.TokenResponse.AccessToken,
                RefreshToken = result.TokenResponse.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
                IdentityToken = result.TokenResponse.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(loginResult.RefreshToken))
            {
                loginResult.RefreshTokenHandler = new RefreshTokenHandler(
                    TokenClientFactory.Create(_options),
                    loginResult.RefreshToken,
                    loginResult.AccessToken);
            }

            return loginResult;
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            _logger.LogTrace("GetUserInfoAsync");

            if (accessToken.IsMissing()) throw new ArgumentNullException(nameof(accessToken));
            if (!_options.ProviderInformation.SupportsUserInfo) throw new InvalidOperationException("No userinfo endpoint specified");

            var userInfoClient = new UserInfoClient(_options.ProviderInformation.UserInfoEndpoint, _options.BackchannelHandler);
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
        /// Refreshes an access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>A token response.</returns>
        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken)
        {
            _logger.LogTrace("RefreshTokenAsync");

            var client = TokenClientFactory.Create(_options);
            var response = await client.RequestRefreshTokenAsync(refreshToken);

            if (response.IsError)
            {
                return new RefreshTokenResult { Error = response.Error };
            }

            // validate token response
            var validationResult = _processor.ValidateTokenResponse(response, null, requireIdentityToken: _options.Policy.RequireIdentityTokenOnRefreshTokenResponse);
            if (validationResult.IsError)
            {
                return new RefreshTokenResult { Error = validationResult.Error };
            }

            return new RefreshTokenResult
            {
                IdentityToken = response.IdentityToken,
                AccessToken = response.AccessToken,
                RefreshToken = response.RefreshToken,
                ExpiresIn = (int)response.ExpiresIn
            };
        }

        internal async Task EnsureConfiguration()
        {
            if (_options.Flow == OidcClientOptions.AuthenticationFlow.Hybrid && _options.Policy.RequireIdentityTokenSignature == false)
            {
                var error = "Allowing unsigned identity tokens is not allowed for hybrid flow";
                _logger.LogError(error);

                throw new InvalidOperationException(error);
            }

            await EnsureProviderInformation();
        }

        internal async Task EnsureProviderInformation()
        {
            _logger.LogTrace("EnsureProviderInformation");

            if (useDiscovery)
            {
                var client = new DiscoveryClient(_options.Authority, _options.BackchannelHandler)
                {
                    Policy = _options.Policy.Discovery,
                    Timeout = _options.BackchannelTimeout
                };
                
                var disco = await client.GetAsync();
                if (disco.IsError)
                {
                    _logger.LogError("Error loading discovery document: {errorType} - {error}", disco.ErrorType.ToString(), disco.Error);

                    throw new InvalidOperationException("Error loading discovery document: " + disco.Error);
                }

                _options.ProviderInformation = new ProviderInformation
                {
                    IssuerName = disco.Issuer,
                    KeySet = disco.KeySet,

                    AuthorizeEndpoint = disco.AuthorizeEndpoint,
                    TokenEndpoint = disco.TokenEndpoint,
                    EndSessionEndpoint = disco.EndSessionEndpoint,
                    UserInfoEndpoint = disco.UserInfoEndpoint,
                    TokenEndPointAuthenticationMethods = disco.TokenEndpointAuthenticationMethodsSupported
                };
            }

            if (_options.ProviderInformation.IssuerName.IsMissing())
            {
                var error = "Issuer name is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.AuthorizeEndpoint.IsMissing())
            {
                var error = "Authorize endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.TokenEndpoint.IsMissing())
            {
                var error = "Token endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.KeySet == null)
            {
                var error = "Key set is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }
        }

        internal ClaimsPrincipal ProcessClaims(ClaimsPrincipal user, IEnumerable<Claim> userInfoClaims)
        {
            _logger.LogTrace("ProcessClaims");

            var combinedClaims = new HashSet<Claim>(new ClaimComparer(compareValueAndTypeOnly: true));

            user.Claims.ToList().ForEach(c => combinedClaims.Add(c));
            userInfoClaims.ToList().ForEach(c => combinedClaims.Add(c));

            var userClaims = new List<Claim>();
            if (_options.FilterClaims)
            {
                userClaims = combinedClaims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToList();
            }
            else
            {
                userClaims = combinedClaims.ToList();
            }

            return new ClaimsPrincipal(new ClaimsIdentity(userClaims, user.Identity.AuthenticationType, user.Identities.First().NameClaimType, user.Identities.First().RoleClaimType));
        }
    }
}