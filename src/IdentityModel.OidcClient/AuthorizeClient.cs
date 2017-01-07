using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// Creates an authorize request and coordinates a web view
    /// </summary>
    public class AuthorizeClient
    {
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
        }

        public async Task<AuthorizeState> CreateAuthorizeStateAsync(object extraParameters = null)
        {
            _logger.LogTrace("CreateAuthorizeStateAsync");

            var state = new AuthorizeState();

            state.Nonce = CryptoRandom.CreateUniqueId(16);
            state.State = CryptoRandom.CreateUniqueId(16);
            state.RedirectUri = _options.RedirectUri;

            string codeChallenge = CreateCodeChallenge(state);
            state.StartUrl = await CreateUrlAsync(state, codeChallenge, extraParameters);

            return state;
        }

        private string CreateCodeChallenge(AuthorizeState state)
        {
            _logger.LogTrace("CreateAuthorizeStateAsync");

            state.CodeVerifier = CryptoRandom.CreateUniqueId(16);

            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(state.CodeVerifier));
                return Base64Url.Encode(challengeBytes);
            }
        }

        private async Task<string> CreateUrlAsync(AuthorizeState state, string codeChallenge, object extraParameters)
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
                throw new InvalidOperationException("Unsupported authentication flow");
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









        /// <summary>
        /// Starts an authorize request using a browser.
        /// </summary>
        /// <param name="trySilent">if set to <c>true</c> try a silent request.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns>The authorize result</returns>
        /// <exception cref="System.InvalidOperationException">No web view configured.</exception>
        //public async Task<AuthorizeResult> AuthorizeAsync(bool trySilent = false, object extraParameters = null)
        //{
        //    if (_options.WebView == null)
        //    {
        //        throw new InvalidOperationException("No web view configured.");
        //    }

        //    InvokeResult wviResult;
        //    AuthorizeResult result = new AuthorizeResult
        //    {
        //        State = await CreateAuthorizeStateAsync(extraParameters)
        //    };

        //    var invokeOptions = new InvokeOptions(result.State.StartUrl, _options.RedirectUri);
        //    invokeOptions.InvisibleModeTimeout = _options.WebViewTimeout;

        //    if (trySilent)
        //    {
        //        invokeOptions.InitialDisplayMode = DisplayMode.Hidden;
        //    }
        //    if (_options.UseFormPost)
        //    {
        //        invokeOptions.ResponseMode = ResponseMode.FormPost;
        //    }

        //    wviResult = await _options.WebView.InvokeAsync(invokeOptions);

        //    if (wviResult.ResultType == InvokeResultType.Success)
        //    {
        //        result.Data = wviResult.Response;
        //        return result;
        //    }

        //    result.Error = wviResult.ResultType.ToString();
        //    return result;
        //}

        /// <summary>
        /// Starts an end_session request using a browser.
        /// </summary>
        /// <param name="identityToken">The identity token.</param>
        /// <param name="trySilent">if set to <c>true</c> try a silent request.</param>
        /// <returns></returns>
        /// <exception cref="System.InvalidOperationException">
        /// No web view defined.
        /// or
        /// no endsession_endpoint defined
        /// </exception>
        //public async Task EndSessionAsync(string identityToken = null, bool trySilent = true)
        //{
        //    if (_options.WebView == null)
        //    {
        //        throw new InvalidOperationException("No web view defined.");
        //    }

        //    string url = (await _options.GetProviderInformationAsync()).EndSessionEndpoint;
        //    if (url.IsMissing())
        //    {
        //        throw new InvalidOperationException("no endsession_endpoint defined");
        //    }

        //    if (!string.IsNullOrWhiteSpace(identityToken))
        //    {
        //        url += $"?{OidcConstants.EndSessionRequest.IdTokenHint}={identityToken}" +
        //               $"&{OidcConstants.EndSessionRequest.PostLogoutRedirectUri}={_options.RedirectUri}";
        //    }

        //    var webViewOptions = new InvokeOptions(url, _options.RedirectUri)
        //    {
        //        ResponseMode = ResponseMode.Redirect,
        //        InvisibleModeTimeout = _options.WebViewTimeout
        //    };

        //    if (trySilent)
        //    {
        //        webViewOptions.InitialDisplayMode = DisplayMode.Hidden;
        //    }

        //    var result = await _options.WebView.InvokeAsync(webViewOptions);
        //}

    }
}
