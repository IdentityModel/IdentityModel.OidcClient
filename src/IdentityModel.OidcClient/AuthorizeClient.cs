using IdentityModel.Client;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    internal class AuthorizeClient
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

        public async Task<AuthorizeResult> AuthorizeAsync(bool invisible = false, object extraParameters = null)
        {
            if (_options.Browser == null)
            {
                throw new InvalidOperationException("No browser configured.");
            }

            AuthorizeResult result = new AuthorizeResult
            {
                State = CreateAuthorizeState(extraParameters)
            };

            var invokeOptions = new BrowserOptions(result.State.StartUrl, _options.RedirectUri);
            invokeOptions.InvisibleModeTimeout = _options.BrowserInvisibleTimeout;

            if (invisible)
            {
                invokeOptions.InitialDisplayMode = DisplayMode.Hidden;
            }
            if (_options.UseFormPost)
            {
                invokeOptions.ResponseMode = ResponseMode.FormPost;
            }

            var browserResult = await _options.Browser.InvokeAsync(invokeOptions);

            if (browserResult.ResultType == BrowserResultType.Success)
            {
                result.Data = browserResult.Response;
                return result;
            }

            result.Error = browserResult.ResultType.ToString();
            return result;
        }


        public AuthorizeState CreateAuthorizeState(object extraParameters = null)
        {
            _logger.LogTrace("CreateAuthorizeStateAsync");

            var pkce = _crypto.CreatePkceData();

            var state = new AuthorizeState
            {
                Nonce = _crypto.CreateNonce(),
                State = _crypto.CreateState(),
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
            switch (_options.Flow)
            {
                case OidcClientOptions.AuthenticationFlow.AuthorizationCode:
                    responseType = OidcConstants.ResponseTypes.Code;
                    break;
                case OidcClientOptions.AuthenticationFlow.Hybrid:
                    responseType = OidcConstants.ResponseTypes.CodeIdToken;
                    break;
                default:
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