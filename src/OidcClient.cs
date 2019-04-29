// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// OpenID Connect client
    /// </summary>
    public class OidcClient
    {
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
        public OidcClientOptions Options { get; private set; }

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
                if (options.Authority.IsMissing()) throw new ArgumentException("No authority specified", nameof(Options.Authority));
                useDiscovery = true;
            }

            Options = options;
            _logger = options.LoggerFactory.CreateLogger<OidcClient>();
            _authorizeClient = new AuthorizeClient(options);
            _processor = new ResponseProcessor(options, EnsureProviderInformationAsync);
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

            if (request == null) throw new ArgumentNullException(nameof(request));

            await EnsureConfigurationAsync();

            var authorizeResult = await _authorizeClient.AuthorizeAsync(new AuthorizeRequest
            {
                DisplayMode = request.BrowserDisplayMode,
                Timeout = request.BrowserTimeout,
                ExtraParameters = request.FrontChannelExtraParameters
            });
            
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
        public virtual async Task<string> PrepareLogoutAsync(LogoutRequest request = default)
        {
            await EnsureConfigurationAsync();

            var endpoint = Options.ProviderInformation.EndSessionEndpoint;
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
        public virtual async Task<LogoutResult> LogoutAsync(LogoutRequest request = default)
        {
            await EnsureConfigurationAsync();

            var result = await _authorizeClient.EndSessionAsync(request);

            if (result.ResultType != Browser.BrowserResultType.Success)
            {
                return new LogoutResult(result.ResultType.ToString())
                {
                    Response = result.Response
                };
            }
            else
            {
                return new LogoutResult
                {
                    Response = result.Response
                };
            }
        }

        /// <summary>
        /// Prepares the login request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>State for initiating the authorize request and processing the response</returns>
        public virtual async Task<AuthorizeState> PrepareLoginAsync(IDictionary<string, string> extraParameters = null)
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
        public virtual async Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state, IDictionary<string, string> extraParameters = null)
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
            if (Options.LoadProfile)
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

            if (loginResult.RefreshToken.IsPresent())
            {
                loginResult.RefreshTokenHandler = new RefreshTokenDelegatingHandler(
                    this,
                    loginResult.AccessToken,
                    loginResult.RefreshToken,
                    Options.RefreshTokenInnerHttpHandler);
            }

            return loginResult;
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>
        /// User claims
        /// </returns>
        /// <exception cref="ArgumentNullException">accessToken</exception>
        /// <exception cref="InvalidOperationException">No userinfo endpoint specified</exception>
        public virtual async Task<UserInfoResult> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("GetUserInfoAsync");

            await EnsureConfigurationAsync();
            if (accessToken.IsMissing()) throw new ArgumentNullException(nameof(accessToken));
            if (!Options.ProviderInformation.SupportsUserInfo) throw new InvalidOperationException("No userinfo endpoint specified");

            var userInfoClient = Options.CreateClient();

            var userInfoResponse = await userInfoClient.GetUserInfoAsync(new UserInfoRequest
            {
                Address = Options.ProviderInformation.UserInfoEndpoint,
                Token = accessToken
            }, cancellationToken).ConfigureAwait(false);

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
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>
        /// A token response.
        /// </returns>
        public virtual async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken, IDictionary<string, string> extraParameters = null, CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("RefreshTokenAsync");

            await EnsureConfigurationAsync();
            var client = Options.CreateClient();
            
            var response = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = Options.ProviderInformation.TokenEndpoint,
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                ClientCredentialStyle = Options.TokenClientCredentialStyle,
                RefreshToken = refreshToken, 
                Parameters = extraParameters ?? new Dictionary<string, string>()
            }, cancellationToken).ConfigureAwait(false);

            if (response.IsError)
            {
                return new RefreshTokenResult { Error = response.Error };
            }

            // validate token response
            var validationResult = await _processor.ValidateTokenResponseAsync(response, null, requireIdentityToken: Options.Policy.RequireIdentityTokenOnRefreshTokenResponse);
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
            if (Options.Flow == OidcClientOptions.AuthenticationFlow.Hybrid && Options.Policy.RequireIdentityTokenSignature == false)
            {
                var error = "Allowing unsigned identity tokens is not allowed for hybrid flow";
                _logger.LogError(error);

                throw new InvalidOperationException(error);
            }

            await EnsureProviderInformationAsync();

            _logger.LogTrace("Effective options:");
            _logger.LogTrace(LogSerializer.Serialize(Options));
        }

        internal async Task EnsureProviderInformationAsync()
        {
            _logger.LogTrace("EnsureProviderInformation");

            if (useDiscovery)
            {
                if (Options.RefreshDiscoveryDocumentForLogin == false)
                {
                    // discovery document has been loaded before - skip reload
                    if (Options.ProviderInformation != null)
                    {
                        _logger.LogDebug("Skipping refresh of discovery document.");

                        return;
                    }
                }

                var discoveryClient = Options.CreateClient();
                var disco = await discoveryClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = Options.Authority,
                    Policy = Options.Policy.Discovery
                }).ConfigureAwait(false);
               
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

                Options.ProviderInformation = new ProviderInformation
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

            if (Options.ProviderInformation.IssuerName.IsMissing())
            {
                var error = "Issuer name is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (Options.ProviderInformation.AuthorizeEndpoint.IsMissing())
            {
                var error = "Authorize endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (Options.ProviderInformation.TokenEndpoint.IsMissing())
            {
                var error = "Token endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (Options.ProviderInformation.KeySet == null)
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
            if (Options.FilterClaims)
            {
                userClaims = combinedClaims.Where(c => !Options.FilteredClaims.Contains(c.Type)).ToList();
            }
            else
            {
                userClaims = combinedClaims.ToList();
            }

            return new ClaimsPrincipal(new ClaimsIdentity(userClaims, user.Identity.AuthenticationType, user.Identities.First().NameClaimType, user.Identities.First().RoleClaimType));
        }
    }
}
