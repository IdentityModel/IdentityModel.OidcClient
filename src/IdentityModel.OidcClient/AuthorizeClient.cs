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

        public async Task<AuthorizeResult> AuthorizeAsync(bool hidden = false, object extraParameters = null)
        {
            if (_options.Browser == null)
            {
                throw new InvalidOperationException("No browser configured.");
            }

            AuthorizeResult result = new AuthorizeResult
            {
                State = CreateAuthorizeState(extraParameters)
            };

            var browserOptions = new BrowserOptions(result.State.StartUrl, _options.RedirectUri);
            browserOptions.Timeout = _options.BrowserTimeout;

            if (hidden)
            {
                browserOptions.DisplayMode = DisplayMode.Hidden;
            }

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

            var parameters = new Dictionary<string, string>
            {
                { OidcConstants.AuthorizeRequest.ResponseType, responseType },   
                { OidcConstants.AuthorizeRequest.Nonce, state.Nonce },
                { OidcConstants.AuthorizeRequest.State, state.State },
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

            return request.Create(parameters);
        }

        private Dictionary<string, string> ObjectToDictionary(object values)
        {
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