// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Jwk;
using IdentityModel.OidcClient.Tests.Infrastructure;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class HybridFlowResponseTests
    {
        OidcClientOptions _options = new OidcClientOptions
        {
            ClientId = "client",
            Scope = "openid profile api",
            RedirectUri = "https://redirect",

            Flow = OidcClientOptions.AuthenticationFlow.Hybrid,
            LoadProfile = false,

            ProviderInformation = new ProviderInformation
            {
                IssuerName = "https://authority",
                AuthorizeEndpoint = "https://authority/authorize",
                TokenEndpoint = "https://authority/token",
                KeySet = new JsonWebKeySet()
            }
        };

        [Fact]
        public async Task Missing_identity_token_should_be_rejected()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=foo";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Missing identity token.");
        }

        [Fact]
        public async Task Valid_response_should_succeed()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce),
                new Claim("c_hash", Crypto.HashData("code")));
            
            var url = $"?state={state.State}&nonce={state.Nonce}&code=code&id_token={frontChannelJwt}";
            
            var backChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", backChannelJwt },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();
        }

        [Fact]
        public async Task Extra_parameters_on_backchannel_should_be_sent()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce),
                new Claim("c_hash", Crypto.HashData("code")));

            var url = $"?state={state.State}&nonce={state.Nonce}&code=code&id_token={frontChannelJwt}";

            var backChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", backChannelJwt },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            var handler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = handler;

            var extra = new Dictionary<string, string>
            {
                { "foo", "foo" },
                { "bar", "bar" }
            };

            var result = await client.ProcessResponseAsync(url, state, extra);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();

            var body = handler.Body;
            body.Should().Contain("foo=foo");
            body.Should().Contain("bar=bar");
        }


        [Fact]
        public async Task Invalid_nonce_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", "invalid"),
                new Claim("c_hash", Crypto.HashData("code")));
            
            var url = $"?state={state.State}&code=code&id_token={frontChannelJwt}";

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Invalid nonce.");
        }

        [Fact]
        public async Task Missing_nonce_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("c_hash", Crypto.HashData("code")));

            var url = $"?state={state.State}&code=code&id_token={frontChannelJwt}";

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Invalid nonce.");
        }

        [Fact]
        public async Task Invalid_cHash_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce),
                new Claim("c_hash", "invalid"));

            var url = $"?state={state.State}&code=code&id_token={frontChannelJwt}";

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Invalid c_hash.");
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task CHash_policy_should_be_enforced(bool requireCHash)
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var url = $"?state={state.State}&nonce={state.Nonce}&code=code&id_token={frontChannelJwt}";

            var backChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", backChannelJwt },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.Policy.RequireAuthorizationCodeHash = requireCHash;

            var result = await client.ProcessResponseAsync(url, state);

            if (requireCHash)
            {
                result.IsError.Should().BeTrue();
                result.Error.Should().Be("c_hash is missing.");
            }
            else
            {
                result.IsError.Should().BeFalse();
                result.AccessToken.Should().Be("token");
                result.IdentityToken.Should().NotBeNull();
                result.User.Should().NotBeNull();
            }
        }

        [Fact]
        public async Task Non_matching_subs_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var key = Crypto.CreateKey();
            var frontChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce),
                new Claim("c_hash", Crypto.HashData("code")));

            var url = $"?state={state.State}&nonce={state.Nonce}&code=code&id_token={frontChannelJwt}";

            var backChannelJwt = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "456"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", backChannelJwt },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Subject on front-channel (123) does not match subject on back-channel (456).");
        }
    }
}