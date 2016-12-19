﻿using IdentityModel.Client;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient.Infrastructure
{
    internal class TokenClientFactory
    {
        public static async Task<TokenClient> CreateAsync(Options options)
        {
            var info = options.ProviderInformation;
            var handler = options.BackchannelHandler ?? new HttpClientHandler();

            TokenClient tokenClient;
            if (options.ClientSecret.IsMissing())
            {
                tokenClient = new TokenClient(info.TokenEndpoint, options.ClientId, handler);
            }
            else
            {
                tokenClient = new TokenClient(info.TokenEndpoint, options.ClientId, options.ClientSecret, handler, options.TokenClientAuthenticationStyle);
            }

            tokenClient.Timeout = options.BackchannelTimeout;

            return tokenClient;
        }
    }
}