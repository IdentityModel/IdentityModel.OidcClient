using IdentityModel.Client;
using IdentityModel.OidcClient.Infrastructure;
using Microsoft.Extensions.Logging;
using System;

namespace IdentityModel.OidcClient
{
     public class AuthorizeClient
    {
        private readonly CryptoHelper _crypto;
        private readonly ILogger<AuthorizeClient> _logger;
        private readonly OidcClientOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizeClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public AuthorizeClient(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<AuthorizeClient>();
            _crypto = new CryptoHelper(options);
        }

        public AuthorizeState CreateAuthorizeState(object extraParameters = null)
        {
            _logger.LogTrace("CreateAuthorizeStateAsync");
            
            var pkce = _crypto.CreatePkceData();

            var state = new AuthorizeState
            {
                Nonce = CryptoRandom.CreateUniqueId(16),
                State = CryptoRandom.CreateUniqueId(16),
                RedirectUri = _options.RedirectUri,
                CodeVerifier = pkce.CodeVerifier,
            };

            state.StartUrl = CreateUrl(state, pkce.CodeChallenge, extraParameters);

            _logger.LogInformation("CreateAuthorizeStateAsync success.");
            _logger.LogInformation(LogSerializer.Serialize(state));

            return state;
        }

        private string CreateUrl(AuthorizeState state, string codeChallenge, object extraParameters)
        {
            _logger.LogTrace("CreateAuthorizeStateAsync");

            var request = new AuthorizeRequest(_options.ProviderInformation.AuthorizeEndpoint);

            string responseType = null;
            if (_options.Flow == OidcClientOptions.AuthenticationFlow.AuthorizationCode)
            {
                responseType = OidcConstants.ResponseTypes.Code;
            }
            else if (_options.Flow == OidcClientOptions.AuthenticationFlow.Hybrid)
            {
                responseType = OidcConstants.ResponseTypes.CodeIdToken;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(_options.Flow), "Unsupported authentication flow");
            }

            var url = request.CreateAuthorizeUrl(
                clientId: _options.ClientId,
                responseType: responseType,
                scope: _options.Scope,
                redirectUri: state.RedirectUri,
                responseMode: _options.UseFormPost ? OidcConstants.ResponseModes.FormPost : null,
                nonce: state.Nonce,
                state: state.State,
                codeChallenge: codeChallenge,
                codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256,
                extra: extraParameters);

            return url;
        }
    }
}