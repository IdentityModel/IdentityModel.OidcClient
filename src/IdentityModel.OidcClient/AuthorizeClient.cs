// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using IdentityModel.OidcClient.WebView;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class AuthorizeClient
    {
        private readonly OidcClientOptions _options;

        public AuthorizeClient(OidcClientOptions options)
        {
            _options = options;
        }

        public async Task<AuthorizeState> PrepareAuthorizeAsync(object extaParameters = null)
        {
            return await CreateAuthorizeStateAsync(extaParameters);
        }

        public async Task<AuthorizeResult> AuthorizeAsync(bool trySilent = false, object extraParameters = null)
        {
            if (_options.WebView == null)
            {
                throw new InvalidOperationException("No web view configured.");
            }

            InvokeResult wviResult;
            AuthorizeResult result = new AuthorizeResult
            {
                Success = false,
                State = await CreateAuthorizeStateAsync(extraParameters)
            };

            var invokeOptions = new InvokeOptions(result.State.StartUrl, _options.RedirectUri);
            invokeOptions.InvisibleModeTimeout = _options.WebViewTimeout;

            if (trySilent)
            {
                invokeOptions.InitialDisplayMode = DisplayMode.Hidden;
            }
            if (_options.UseFormPost)
            {
                invokeOptions.ResponseMode = ResponseMode.FormPost;
            }

            wviResult = await _options.WebView.InvokeAsync(invokeOptions);

            if (wviResult.ResultType == InvokeResultType.Success)
            {
                result.Success = true;
                result.Data = wviResult.Response;

                return result;
            }

            result.Error = wviResult.ResultType.ToString();
            return result;
        }

        public async Task EndSessionAsync(string identityToken = null, bool trySilent = true)
        {
            if (_options.WebView == null)
            {
                throw new InvalidOperationException("No web view defined.");
            }

            string url = (await _options.GetDiscoveryDocument()).EndSessionEndpoint;
            if (url.IsMissing())
            {
                throw new InvalidOperationException("no endsession_endpoint defined");
            }

            if (!string.IsNullOrWhiteSpace(identityToken))
            {
                url += $"?{OidcConstants.EndSessionRequest.IdTokenHint}={identityToken}" +
                       $"&{OidcConstants.EndSessionRequest.PostLogoutRedirectUri}={_options.RedirectUri}";
            }

            var webViewOptions = new InvokeOptions(url, _options.RedirectUri)
            {
                ResponseMode = ResponseMode.Redirect,
                InvisibleModeTimeout = _options.WebViewTimeout
            };

            if (trySilent)
            {
                webViewOptions.InitialDisplayMode = DisplayMode.Hidden;
            }

            var result = await _options.WebView.InvokeAsync(webViewOptions);
        }

        private async Task<AuthorizeState> CreateAuthorizeStateAsync(object extraParameters = null)
        {
            var state = new AuthorizeState();

            state.Nonce = CryptoRandom.CreateUniqueId();
            state.State = CryptoRandom.CreateUniqueId();
            state.RedirectUri = _options.RedirectUri;

            string codeChallenge = CreateCodeChallenge(state);
            state.StartUrl = await CreateUrlAsync(state, codeChallenge, extraParameters);

            return state;
        }

        private string CreateCodeChallenge(AuthorizeState state)
        {
            state.CodeVerifier = CryptoRandom.CreateUniqueId();

            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(state.CodeVerifier));
                return Base64Url.Encode(challengeBytes);
            }
        }

        private async Task<string> CreateUrlAsync(AuthorizeState state, string codeChallenge, object extraParameters)
        {
            var request = new AuthorizeRequest((await _options.GetDiscoveryDocument()).AuthorizationEndpoint);

            string responseType = null;
            if (_options.Style == OidcClientOptions.AuthenticationStyle.AuthorizationCode)
            {
                responseType = OidcConstants.ResponseTypes.Code;
            }
            else if(_options.Style == OidcClientOptions.AuthenticationStyle.Hybrid)
            {
                responseType = OidcConstants.ResponseTypes.CodeIdToken;
            }
            else
            {
                throw new InvalidOperationException("Unsupported authentication style");
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