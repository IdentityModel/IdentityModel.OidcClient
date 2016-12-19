using IdentityModel.OidcClient.WebView;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace IdentityModel.OidcClient
{
    public class Options
    {
        public string Authority { get; set; }
        public ProviderInformation ProviderInformation { get; set; }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; }
        public string RedirectUri { get; }

        public IWebView WebView { get; }
        public IIdentityTokenValidator IdentityTokenValidator { get; }

        public bool UseFormPost { get; set; } = false;
        public bool LoadProfile { get; set; } = true;
        public bool FilterClaims { get; set; } = true;
        public AuthenticationStyle Style = AuthenticationStyle.Hybrid;

        public HttpMessageHandler BackchannelHandler { get; set; }
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

        public enum AuthenticationStyle
        {
            AuthorizationCode,
            Hybrid
        }
    }
}
