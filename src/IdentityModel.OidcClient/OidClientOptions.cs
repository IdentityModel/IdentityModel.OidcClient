// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.WebView;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace IdentityModel.OidcClient
{
    public class OidcClientOptions
    {
        public string Authority { get; set; }
        public ProviderInformation ProviderInformation { get; set; }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }
        public string RedirectUri { get; set; }

        public IWebView WebView { get; set; }
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        public bool UseFormPost { get; set; } = false;
        public bool LoadProfile { get; set; } = true;
        public bool FilterClaims { get; set; } = true;
        public AuthenticationFlow Flow = AuthenticationFlow.Hybrid;

        public HttpMessageHandler BackchannelHandler { get; set; } = new HttpClientHandler();
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(30);
        public Client.AuthenticationStyle TokenClientAuthenticationStyle { get; set; } = Client.AuthenticationStyle.PostValues;

        public Policy Policy { get; set; } = new Policy();
        public ILoggerFactory LoggerFactory { get; } = new LoggerFactory();

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

        public enum AuthenticationFlow
        {
            AuthorizationCode,
            Hybrid
        }
    }
}
