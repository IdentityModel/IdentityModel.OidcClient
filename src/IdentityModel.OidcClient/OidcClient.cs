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
        public OidcClient(OidcClientOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.ProviderInformation == null) useDiscovery = true;

            _options = options;
            _logger = options.LoggerFactory.CreateLogger<OidcClient>();
            _authorizeClient = new AuthorizeClient(options);
            _processor = new ResponseProcessor(options);
        }

        // <summary>
        // Prepares an authentication request.
        // </summary>
        // <param name = "extraParameters" > extra parameters to send to the authorize endpoint.</param>
        // <returns>An authorize state object that can be later used to validate the response</returns>
        public async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            _logger.LogTrace("PrepareLoginAsync");

            await EnsureConfiguration();
            return _authorizeClient.CreateAuthorizeState(extraParameters);
        }

        /// <summary>
        /// Validates the response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <returns>Result of the login response validation</returns>

        public async Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state)
        {
            _logger.LogTrace("ValidateResponseAsync");

            var response = new AuthorizeResponse(data);

            if (response.IsError)
            {
                _logger.LogError(response.Error);
                return new LoginResult(response.Error);
            }

            var validationResult = await _processor.ProcessResponseAsync(response, state);
            if (validationResult.IsError)
            {
                _logger.LogError("Error validating response: " + validationResult.Error);
                return new LoginResult(validationResult.Error);
            }

            return await ProcessClaimsAsync(validationResult);
        }

        private async Task EnsureConfiguration()
        {
            if (_options.ClientId.IsMissing())
            {
                _logger.LogError("No client id configured");
                throw new ArgumentNullException(_options.ClientId);
            }

            if (_options.Scope.IsMissing())
            {
                _logger.LogError("No scopes configured");
                throw new ArgumentNullException(_options.Scope);
            }

            if (_options.RedirectUri.IsMissing())
            {
                _logger.LogError("No redirect URI configured");
                throw new ArgumentNullException(_options.RedirectUri);
            }

            await EnsureProviderInformation();
        }

        private async Task EnsureProviderInformation()
        {
            _logger.LogTrace("EnsureProviderInformation");

            if (useDiscovery)
            {
                var client = new DiscoveryClient(_options.Authority, _options.BackchannelHandler);
                client.Policy = _options.Policy.Discovery;

                var disco = await client.GetAsync();
                if (disco.IsError)
                {
                    _logger.LogError("Error loading discovery document: {errorType} - {error}", disco.ErrorType.ToString(), disco.Error);

                    throw new InvalidOperationException("Error loading discovery document: " + disco.Error);
                }

                if (disco.Issuer.IsMissing())
                {
                    var error = "Issuer name is missing in discovery document";

                    _logger.LogError(error);
                    throw new InvalidOperationException(error);
                }

                if (disco.AuthorizeEndpoint.IsMissing())
                {
                    var error = "Authorize endpoint is missing in discovery document";

                    _logger.LogError(error);
                    throw new InvalidOperationException(error);
                }

                if (disco.TokenEndpoint.IsMissing())
                {
                    var error = "Token endpoint is missing in discovery document";

                    _logger.LogError(error);
                    throw new InvalidOperationException(error);
                }

                if (disco.JwksUri.IsMissing() || disco.KeySet == null)
                {
                    var error = "Key set is missing in discovery document";

                    _logger.LogError(error);
                    throw new InvalidOperationException(error);
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
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
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

        private async Task<LoginResult> ProcessClaimsAsync(ResponseValidationResult result)
        {
            _logger.LogTrace("ProcessClaimsAsync");

            // get profile if enabled
            if (_options.LoadProfile)
            {
                //Logger.Debug("load profile");

                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);

                if (userInfoResult.IsError)
                {
                    return new LoginResult(userInfoResult.Error);
                }

                _logger.LogDebug("profile claims:");
                _logger.LogClaims(userInfoResult.Claims);

                var primaryClaimTypes = result.User.Claims.Select(c => c.Type).Distinct();
                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
                {
                    result.User.Identities.First().AddClaim(claim);
                }
            }
            else
            {
                //Logger.Debug("don't load profile");
            }

            // success
            var loginResult = new LoginResult
            {
                User = FilterClaims(result.User),
                AccessToken = result.TokenResponse.AccessToken,
                RefreshToken = result.TokenResponse.RefreshToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
                IdentityToken = result.TokenResponse.IdentityToken,
                AuthenticationTime = DateTime.Now
            };

            if (!string.IsNullOrWhiteSpace(result.TokenResponse.RefreshToken))
            {
                loginResult.RefreshTokenHandler = new RefreshTokenHandler(
                    TokenClientFactory.Create(_options),
                    result.TokenResponse.RefreshToken,
                    result.TokenResponse.AccessToken);
            }

            return loginResult;
        }

        private ClaimsPrincipal FilterClaims(ClaimsPrincipal user)
        {
            _logger.LogTrace("filtering claims");

            var claims = new List<Claim>();
            if (_options.FilterClaims)
            {
                claims = user.Claims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToList();
            }

            _logger.LogDebug("filtered claims:");
            _logger.LogClaims(claims);

            return new ClaimsPrincipal(new ClaimsIdentity(claims, user.Identity.AuthenticationType, user.Identities.First().NameClaimType, user.Identities.First().RoleClaimType));
        }
    }
}