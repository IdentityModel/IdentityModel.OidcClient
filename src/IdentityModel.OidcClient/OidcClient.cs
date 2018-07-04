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
            _processor = new ResponseProcessor(options, EnsureProviderInformationAsync);
        }

        /// <summary>
        /// Starts a login.
        /// </summary>
        /// <param name="displayMode">The browser display mode.</param>
        /// <param name="timeout">The browser timeout.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns></returns>
        [Obsolete("This method will be removed in a future version. Please change your code to use LoginRequest")]
        public virtual async Task<LoginResult> LoginAsync(DisplayMode displayMode = DisplayMode.Visible, int timeout = 300, object extraParameters = null)
        {
            return await LoginAsync(new LoginRequest
            {
                BrowserDisplayMode = displayMode,
                BrowserTimeout = timeout,
                FrontChannelExtraParameters = extraParameters
            });
        }

        /// <summary>
        /// Starts a login.
        /// </summary>
        /// <param name="request">The login request.</param>
        /// <returns></returns>
        public virtual async Task<LoginResult> LoginAsync(LoginRequest request)
        {
            _logger.LogTrace("LoginAsync");
            _logger.LogInformation("Starting authentication request.");

            // fallback to defaults 
            if (request == null) request = new LoginRequest();

            await EnsureConfigurationAsync();
            var authorizeResult = await _authorizeClient.AuthorizeAsync(request.BrowserDisplayMode, request.BrowserTimeout, request.FrontChannelExtraParameters);

            if (authorizeResult.IsError)
            {
                return new LoginResult(authorizeResult.Error);
            }

            var result = await ProcessResponseAsync(authorizeResult.Data, authorizeResult.State, request.BackChannelExtraParameters);

            if (!result.IsError)
            {
                _logger.LogInformation("Authentication request success.");
            }

            return result;
        }

        /// <summary>
        /// Creates a logout URL.
        /// </summary>
        /// <param name="request">The logout request.</param>
        /// <returns></returns>
        public virtual async Task<string> PrepareLogoutAsync(LogoutRequest request = null)
        {
            if (request == null) request = new LogoutRequest();
            await EnsureConfigurationAsync();

            var endpoint = _options.ProviderInformation.EndSessionEndpoint;
            if (endpoint.IsMissing())
            {
                throw new InvalidOperationException("Discovery document has no end session endpoint");
            }

            return _authorizeClient.CreateEndSessionUrl(endpoint, request);
        }

        /// <summary>
        /// Starts a logout.
        /// </summary>
        /// <param name="request">The logout request.</param>
        /// <returns></returns>
        public virtual async Task LogoutAsync(LogoutRequest request = null)
        {
            if (request == null) request = new LogoutRequest();
            await EnsureConfigurationAsync();

            await _authorizeClient.EndSessionAsync(request);
        }

        /// <summary>
        /// Prepares the login request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>State for initiating the authorize request and processing the response</returns>
        public virtual async Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null)
        {
            _logger.LogTrace("PrepareLoginAsync");

            await EnsureConfigurationAsync();
            return _authorizeClient.CreateAuthorizeState(extraParameters);
        }

        /// <summary>
        /// Processes the authorize response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns>
        /// Result of the login response validation
        /// </returns>
        public virtual async Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state, object extraParameters = null)
        {
            _logger.LogTrace("ProcessResponseAsync");
            _logger.LogInformation("Processing response.");

            await EnsureConfigurationAsync();

            _logger.LogDebug("Authorize response: {response}", data);
            var authorizeResponse = new AuthorizeResponse(data);

            if (authorizeResponse.IsError)
            {
                _logger.LogError(authorizeResponse.Error);
                return new LoginResult(authorizeResponse.Error);
            }

            var result = await _processor.ProcessResponseAsync(authorizeResponse, state, extraParameters);
            if (result.IsError)
            {
                _logger.LogError(result.Error);
                return new LoginResult(result.Error);
            }

            var userInfoClaims = Enumerable.Empty<Claim>();
            if (_options.LoadProfile)
            {
                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);
                if (userInfoResult.IsError)
                {
                    var error = $"Error contacting userinfo endpoint: {userInfoResult.Error}";
                    _logger.LogError(error);

                    return new LoginResult(error);
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
                    loginResult.AccessToken,
                    _options.RefreshTokenInnerHttpHandler);
            }

            return loginResult;
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        public virtual async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            _logger.LogTrace("GetUserInfoAsync");

            await EnsureConfigurationAsync();
            if (accessToken.IsMissing()) throw new ArgumentNullException(nameof(accessToken));
            if (!_options.ProviderInformation.SupportsUserInfo) throw new InvalidOperationException("No userinfo endpoint specified");

            var userInfoClient = new UserInfoClient(_options.ProviderInformation.UserInfoEndpoint, _options.BackchannelHandler)
            {
                Timeout = _options.BackchannelTimeout
            };

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
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns>
        /// A token response.
        /// </returns>
        public virtual async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken, object extraParameters = null)
        {
            _logger.LogTrace("RefreshTokenAsync");

            await EnsureConfigurationAsync();
            var client = TokenClientFactory.Create(_options);
            var response = await client.RequestRefreshTokenAsync(refreshToken, extra: extraParameters);

            if (response.IsError)
            {
                return new RefreshTokenResult { Error = response.Error };
            }

            // validate token response
            var validationResult = await _processor.ValidateTokenResponseAsync(response, null, requireIdentityToken: _options.Policy.RequireIdentityTokenOnRefreshTokenResponse);
            if (validationResult.IsError)
            {
                return new RefreshTokenResult { Error = validationResult.Error };
            }

            return new RefreshTokenResult
            {
                IdentityToken = response.IdentityToken,
                AccessToken = response.AccessToken,
                RefreshToken = response.RefreshToken,
                ExpiresIn = (int)response.ExpiresIn,
                AccessTokenExpiration = DateTime.Now.AddSeconds(response.ExpiresIn)
            };
        }

        internal async Task EnsureConfigurationAsync()
        {
            if (_options.Flow == OidcClientOptions.AuthenticationFlow.Hybrid && _options.Policy.RequireIdentityTokenSignature == false)
            {
                var error = "Allowing unsigned identity tokens is not allowed for hybrid flow";
                _logger.LogError(error);

                throw new InvalidOperationException(error);
            }

            await EnsureProviderInformationAsync();

            _logger.LogTrace("Effective options:");
            _logger.LogTrace(LogSerializer.Serialize(_options));
        }

        internal async Task EnsureProviderInformationAsync()
        {
            _logger.LogTrace("EnsureProviderInformation");

            if (useDiscovery)
            {
                if (_options.RefreshDiscoveryDocumentForLogin == false)
                {
                    // discovery document has been loaded before - skip reload
                    if (_options.ProviderInformation != null)
                    {
                        _logger.LogDebug("Skipping refresh of discovery document.");

                        return;
                    }
                }

                var client = new DiscoveryClient(_options.Authority, _options.BackchannelHandler)
                {
                    Policy = _options.Policy.Discovery,
                    Timeout = _options.BackchannelTimeout
                };

                var disco = await client.GetAsync().ConfigureAwait(false);
                
                if (disco.IsError)
                {
                    _logger.LogError("Error loading discovery document: {errorType} - {error}", disco.ErrorType.ToString(), disco.Error);
                    
                    if (disco.ErrorType == ResponseErrorType.Exception)
                    {
                        throw new InvalidOperationException("Error loading discovery document: " + disco.Error, disco.Exception);
                    }

                    throw new InvalidOperationException("Error loading discovery document: " + disco.Error);
                }

                _logger.LogDebug("Successfully loaded discovery document");
                _logger.LogDebug("Loaded keyset from {jwks_uri}", disco.JwksUri);
                _logger.LogDebug("Keyset contains the following kids: {kids}", from k in disco.KeySet.Keys select k.Kid ?? "unspecified");

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
