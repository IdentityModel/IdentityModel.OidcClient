// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class OidcClientTests
    {
        [Fact]
        public async Task RefreshTokenAsync_with_scope_should_set_http_request_scope_parameter()
        {
            var scope = Guid.NewGuid().ToString();
            var sut = new OidcClient(new OidcClientOptions
            {
                Authority = "https://exemple.com",
                ProviderInformation = new ProviderInformation
                {
                    IssuerName = "https://exemple.com",
                    AuthorizeEndpoint = "https://exemple.com/connect/authorize",
                    TokenEndpoint = "https://exemple.com/connect/token"
                },
                Policy = new Policy
                {
                    Discovery = new Client.DiscoveryPolicy
                    {
                        RequireKeySet = false,
                    }
                },
                ClientId = "test",
                Scope = "openid profile offline_access",
                RedirectUri = "test://authentication/login-callback",               
                HttpClientFactory = o =>
                {
                    return new HttpClient(new FakeHttpMessageHandler
                    {
                        Func = async r =>
                        {
                            var content = await r.Content.ReadAsStringAsync();
                            Assert.Contains($"scope={scope}", content);
                            return new HttpResponseMessage
                                {
                                    Content = new StringContent($@"{{
  ""access_token"": ""23af3183-a712-40c7-86f8-d784705c8a78"",
  ""refresh_token"": ""23af3183-a712-40c7-86f8-d784705c8a79"",
  ""expires_in"": 3600,
  ""token_type"": ""Bearer"",
  ""scope"": ""{scope}""
}}")
                                };
                        }
                    });
                }
            });

            var result = await sut.RefreshTokenAsync("test", scope: scope);

            Assert.NotNull(result);
        }

        class FakeHttpMessageHandler : HttpMessageHandler
        {
            public Func<HttpRequestMessage, Task<HttpResponseMessage>> Func { get; set; }
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Func(request);
        }
    }
}
