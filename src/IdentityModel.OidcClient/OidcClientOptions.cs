// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using IdentityModel.OidcClient.IdentityTokenValidation;
using IdentityModel.OidcClient.WebView;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// Configuration options for the OidcClient
    /// </summary>
    public class OidcClientOptions
    {
        private readonly Lazy<Task<DiscoveryResponse>> _providerInfo;

        /// <summary>
        /// Gets the client id.
        /// </summary>
        /// <value>
        /// The client identifier.
        /// </value>
        public string ClientId { get; }


        /// <summary>
        /// Gets the client secret.
        /// </summary>
        /// <value>
        /// The client secret.
        /// </value>
        public string ClientSecret { get; }

        /// <summary>
        /// Gets the scope.
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope { get; }

        /// <summary>
        /// Gets the redirect URI.
        /// </summary>
        /// <value>
        /// The redirect URI.
        /// </value>
        public string RedirectUri { get; }

        /// <summary>
        /// Gets the web view implementation.
        /// </summary>
        /// <value>
        /// The web view.
        /// </value>
        public IWebView WebView { get; }

        /// <summary>
        /// Gets the identity token validator.
        /// </summary>
        /// <value>
        /// The identity token validator.
        /// </value>
        public IIdentityTokenValidator IdentityTokenValidator { get; }

        /// <summary>
        /// Gets or sets a value indicating whether a form post is used in the authorize response.
        /// </summary>
        /// <value>
        ///   <c>true</c> if form_post is used; otherwise, <c>false</c>.
        /// </value>
        public bool UseFormPost { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the userinfo endpoint is used to load user claims
        /// </summary>
        /// <value>
        ///   <c>true</c> if the profile is loaded; otherwise, <c>false</c>.
        /// </value>
        public bool LoadProfile { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether claims should be filtered.
        /// </summary>
        /// <value>
        ///   <c>true</c> if claims will be fitered; otherwise, <c>false</c>.
        /// </value>
        public bool FilterClaims { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the issuer name is validated to make sure matches the authority.
        /// </summary>
        /// <value>
        ///   <c>true</c> if issuer name gets validated; otherwise, <c>false</c>.
        /// </value>
        public bool ValidateIssuerName { get; set; } = true;

        /// <summary>
        /// Gets or sets the authentication style (basic authorization code vs hybrid).
        /// </summary>
        /// <value>
        /// The style.
        /// </value>
        public AuthenticationStyle Style { get; set; } = AuthenticationStyle.Hybrid;

        /// <summary>
        /// Gets or sets the web view timeout.
        /// </summary>
        /// <value>
        /// The web view timeout.
        /// </value>
        public TimeSpan WebViewTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Gets or sets the token client authentication style.
        /// </summary>
        /// <value>
        /// The token client authentication style.
        /// </value>
        public Client.AuthenticationStyle TokenClientAuthenticationStyle { get; set; } = Client.AuthenticationStyle.BasicAuthentication;

        /// <summary>
        /// Gets or sets the backchannel timeout.
        /// </summary>
        /// <value>
        /// The backchannel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the backchannel handler.
        /// </summary>
        /// <value>
        /// The backchannel handler.
        /// </value>
        public HttpMessageHandler BackchannelHandler { get; set; }

        /// <summary>
        /// Gets or sets the claims filter.
        /// </summary>
        /// <value>
        /// The filtered claims.
        /// </value>
        public ICollection<string> FilteredClaims { get; set; } = new HashSet<string>
        {
            JwtClaimTypes.Issuer,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.Audience,
            JwtClaimTypes.Nonce,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.AuthenticationTime,
            JwtClaimTypes.AuthorizationCodeHash,
            JwtClaimTypes.AccessTokenHash
        };

        private OidcClientOptions(string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));
            if (string.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentNullException(nameof(redirectUri));

            // make sure the scopes contain openid
            if (!scope.FromSpaceSeparatedString().Contains("openid"))
            {
                throw new ArgumentException("Scope must include openid", nameof(scope));
            }

            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
            RedirectUri = redirectUri;
            IdentityTokenValidator = validator ?? new DefaultIdentityTokenValidator();
            WebView = webView;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OidcClientOptions"/> class.
        /// </summary>
        /// <param name="info">The provider information.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="webView">The web view.</param>
        /// <param name="validator">The validator.</param>
        /// <exception cref="System.ArgumentNullException">info</exception>
        //public OidcClientOptions(ProviderInformation info, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
        //    : this(clientId, clientSecret, scope, redirectUri, webView, validator)
        //{
        //    if (info == null) throw new ArgumentNullException(nameof(info));
        //    info.Validate();

        //    _providerInfo = new Lazy<Task<ProviderInformation>>(() => Task.FromResult(info));
        //}

        /// <summary>
        /// Initializes a new instance of the <see cref="OidcClientOptions"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="webView">The web view.</param>
        /// <param name="validator">The validator.</param>
        /// <exception cref="System.ArgumentNullException">authority</exception>
        public OidcClientOptions(string authority, string clientId, string clientSecret, string scope, string redirectUri, IWebView webView = null, IIdentityTokenValidator validator = null)
            : this(clientId, clientSecret, scope, redirectUri, webView, validator)
        {
            if (string.IsNullOrWhiteSpace(authority)) throw new ArgumentNullException(nameof(authority));

            _providerInfo = new Lazy<Task<DiscoveryResponse>>(async () => await DiscoveryClient.GetAsync(authority); //, ValidateIssuerName, BackchannelHandler, (int)BackchannelTimeout.TotalSeconds));
        }

        /// <summary>
        /// Gets the provider information.
        /// </summary>
        /// <returns></returns>
        public async Task<ProviderInformation> GetProviderInformationAsync()
        {
            return await _providerInfo.Value;
        }

        /// <summary>
        /// The authentication style
        /// </summary>
        public enum AuthenticationStyle
        {
            AuthorizationCode,
            Hybrid
        }
    }
}