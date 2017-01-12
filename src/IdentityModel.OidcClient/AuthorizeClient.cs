using IdentityModel.Client;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Reflection;
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

        public async Task<AuthorizeResult> AuthorizeAsync(DisplayMode displayMode = DisplayMode.Visible, int timeout = 300, object extraParameters = null)
        {
            _logger.LogTrace("AuthorizeAsync");

            if (_options.Browser == null)
            {
                throw new InvalidOperationException("No browser configured.");
            }

            AuthorizeResult result = new AuthorizeResult
            {
                State = CreateAuthorizeState(extraParameters)
            };

            var browserOptions = new BrowserOptions(result.State.StartUrl, _options.RedirectUri)
            {
                Timeout = TimeSpan.FromSeconds(timeout),
                DisplayMode = displayMode
            };

            if (_options.ResponseMode == OidcClientOptions.AuthorizeResponseMode.FormPost)
            {
                browserOptions.ResponseMode = OidcClientOptions.AuthorizeResponseMode.FormPost;
            }
            else
            {
                browserOptions.ResponseMode = OidcClientOptions.AuthorizeResponseMode.Redirect;
            }

            var browserResult = await _options.Browser.InvokeAsync(browserOptions);

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

            state.StartUrl = CreateUrl(state.State, state.Nonce, pkce.CodeChallenge, extraParameters);

            _logger.LogInformation("CreateAuthorizeStateAsync success.");
            _logger.LogInformation(LogSerializer.Serialize(state));

            return state;
        }

        internal string CreateUrl(string state, string nonce, string codeChallenge, object extraParameters)
        {
            _logger.LogTrace("CreateUrl");

            var parameters = CreateParameters(state, nonce, codeChallenge, extraParameters);
            var request = new AuthorizeRequest(_options.ProviderInformation.AuthorizeEndpoint);

            return request.Create(parameters);
        }

        internal Dictionary<string, string> CreateParameters(string state, string nonce, string codeChallenge, object extraParameters)
        {
            _logger.LogTrace("CreateParameters");

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

            var parameters = new Dictionary<string, string>
            {
                { OidcConstants.AuthorizeRequest.ResponseType, responseType },
                { OidcConstants.AuthorizeRequest.Nonce, nonce },
                { OidcConstants.AuthorizeRequest.State, state },
                { OidcConstants.AuthorizeRequest.CodeChallenge, codeChallenge },
                { OidcConstants.AuthorizeRequest.CodeChallengeMethod, OidcConstants.CodeChallengeMethods.Sha256 },
            };

            if (_options.ClientId.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.ClientId, _options.ClientId);
            }
            if (_options.Scope.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.Scope, _options.Scope);
            }
            if (_options.RedirectUri.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.RedirectUri, _options.RedirectUri);
            }
            if (_options.ResponseMode == OidcClientOptions.AuthorizeResponseMode.FormPost)
            {
                parameters.Add(OidcConstants.AuthorizeRequest.ResponseMode, OidcConstants.ResponseModes.FormPost);
            }

            var extraDictionary = ObjectToDictionary(extraParameters);
            if (extraDictionary != null)
            {
                foreach (var entry in extraDictionary)
                {
                    if (!string.IsNullOrWhiteSpace(entry.Value))
                    {
                        if (parameters.ContainsKey(entry.Key))
                        {
                            parameters[entry.Key] = entry.Value;
                        }
                        else
                        {
                            parameters.Add(entry.Key, entry.Value);
                        }
                    }
                }
            }

            return parameters;
        }

        private Dictionary<string, string> ObjectToDictionary(object values)
        {
            _logger.LogTrace("ObjectToDictionary");

            if (values == null)
            {
                return null;
            }

            var dictionary = values as Dictionary<string, string>;
            if (dictionary != null) return dictionary;

            dictionary = new Dictionary<string, string>();

            foreach (var prop in values.GetType().GetRuntimeProperties())
            {
                var value = prop.GetValue(values) as string;
                if (!string.IsNullOrEmpty(value))
                {
                    dictionary.Add(prop.Name, value);
                }
            }

            return dictionary;
        }
    }
}