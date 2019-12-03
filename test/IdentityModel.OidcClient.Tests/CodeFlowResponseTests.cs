// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Jwk;
using IdentityModel.OidcClient.Tests.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class CodeFlowResponseTests
    {
        OidcClientOptions _options = new OidcClientOptions
        {
            ClientId = "client",
            Scope = "openid profile api",
            RedirectUri = "https://redirect",

            LoadProfile = false,

            ProviderInformation = new ProviderInformation
            {
                IssuerName = "https://authority",
                AuthorizeEndpoint = "https://authority/authorize",
                TokenEndpoint = "https://authority/token",
                UserInfoEndpoint = "https://authority/userinfo",
                KeySet = new JsonWebKeySet()
            }
        };

        [Fact]
        public async Task Valid_response_should_succeed()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();

            result.User.Claims.Count().Should().Be(1);
            result.User.Claims.First().Type.Should().Be("sub");
            result.User.Claims.First().Value.Should().Be("123");
        }

        [Fact]
        public async Task Valid_response_with_profile_should_succeed()
        {
            _options.LoadProfile = true;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            var userinfoResponse = new Dictionary<string, object>
            {
                { "sub", "123" },
                { "name", "Dominick" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var networkHandler = new NetworkHandler(request =>
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("token"))
                {
                    return JsonConvert.SerializeObject(tokenResponse);
                }
                else if (request.RequestUri.AbsoluteUri.EndsWith("userinfo"))
                {
                    return JsonConvert.SerializeObject(userinfoResponse);
                }
                else
                {
                    throw new InvalidOperationException("unknown netowrk request.");
                }

            }, HttpStatusCode.OK);

            _options.BackchannelHandler = networkHandler;

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();

            result.User.Claims.Count().Should().Be(2);
            result.User.Claims.First().Type.Should().Be("sub");
            result.User.Claims.First().Value.Should().Be("123");
            result.User.Claims.Skip(1).First().Type.Should().Be("name");
            result.User.Claims.Skip(1).First().Value.Should().Be("Dominick");
        }

        [Fact]
        public async Task Sending_authorization_header_should_succeed()
        {
            _options.ClientSecret = "secret";
            _options.TokenClientCredentialStyle = Client.ClientCredentialStyle.AuthorizationHeader;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var backChannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = backChannelHandler;

            var result = await client.ProcessResponseAsync(url, state);

            var request = backChannelHandler.Request;

            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Scheme.Should().Be("Basic");
            request.Headers.Authorization.Parameter.Should().Be(BasicAuthenticationOAuthHeaderValue.EncodeCredential("client", "secret"));
        }

        [Fact]
        public async Task Sending_client_credentials_in_body_should_succeed()
        {
            _options.ClientSecret = "secret";
            _options.TokenClientCredentialStyle = Client.ClientCredentialStyle.PostBody;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var backChannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = backChannelHandler;

            var result = await client.ProcessResponseAsync(url, state);

            var fields = QueryHelpers.ParseQuery(backChannelHandler.Body);
            fields["client_id"].First().Should().Be("client");
            fields["client_secret"].First().Should().Be("secret");
        }

        [Fact]
        public async Task Multi_tenant_token_issuer_name_should_succeed_by_policy_option()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            _options.Policy.Discovery.ValidateEndpoints = false;
            _options.Policy.ValidateTokenIssuerName = false;

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://{some_multi_tenant_name}", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
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

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
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

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", "invalid"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Error validating token response: Invalid nonce.");
        }

        [Fact]
        public async Task Missing_nonce_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Error validating token response: Invalid nonce.");
        }


        [Fact]
        public async Task Error_redeeming_code_should_fail()
        {
            _options.BackchannelHandler = new NetworkHandler(new Exception("error"));

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().StartWith("Error redeeming code: error");
        }

        [Fact]
        public async Task Missing_access_token_on_token_response_should_fail()
        {
            var tokenResponse = new Dictionary<string, object>
            {
                //{ "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", "id_token" },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Error validating token response: Access token is missing on token response.");
        }

        [Fact]
        public async Task No_identity_token_on_token_response_and_no_profile_loading_should_succeed()
        {
            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().BeNull();
            
            result.User.Should().NotBeNull();
            result.User.Claims.Count().Should().Be(0);
        }

        [Fact]
        public async Task No_identity_token_on_token_response_with_profile_loading_should_succeed()
        {
            _options.LoadProfile = true;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "refresh_token", "refresh_token" }
            };

            var userinfoResponse = new Dictionary<string, object>
            {
                { "sub", "123" },
                { "name", "Dominick" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);

            var networkHandler = new NetworkHandler(request =>
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("token"))
                {
                    return JsonConvert.SerializeObject(tokenResponse);
                }
                else if (request.RequestUri.AbsoluteUri.EndsWith("userinfo"))
                {
                    return JsonConvert.SerializeObject(userinfoResponse);
                }
                else
                {
                    throw new InvalidOperationException("unknown netowrk request.");
                }

            }, HttpStatusCode.OK);

            _options.BackchannelHandler = networkHandler;

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().BeNull();
            result.User.Should().NotBeNull();

            result.User.Claims.Count().Should().Be(2);
            result.User.Claims.First().Type.Should().Be("sub");
            result.User.Claims.First().Value.Should().Be("123");
            result.User.Claims.Skip(1).First().Type.Should().Be("name");
            result.User.Claims.Skip(1).First().Value.Should().Be("Dominick");
        }

        [Fact]
        public async Task Malformed_identity_token_on_token_response_should_fail()
        {
            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", "id_token" },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("IDX12709");
        }

        [Fact]
        public async Task No_keyset_for_identity_token_should_fail()
        {
            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", Crypto.UntrustedIdentityToken },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("IDX10501");
        }

        [Fact]
        public async Task Untrusted_identity_token_should_fail()
        {
            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", Crypto.UntrustedIdentityToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(Crypto.CreateKey());
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("IDX10501: Signature validation failed");
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task At_hash_policy_should_be_enforced(bool atHashRequired)
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));
                
            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.Policy.RequireAccessTokenHash = atHashRequired;

            var result = await client.ProcessResponseAsync(url, state);

            if (atHashRequired)
            {
                result.IsError.Should().BeTrue();
                result.Error.Should().Be("Error validating token response: at_hash is missing.");
            }
            else
            {
                result.IsError.Should().BeFalse();
                result.AccessToken.Should().Be("token");
                result.IdentityToken.Should().NotBeNull();
                result.User.Should().NotBeNull();
            }
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task Invalid_at_hash_should_fail(bool atHashRequired)
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&nonce={state.Nonce}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", "invalid"),
                new Claim("sub", "123"),
                new Claim("nonce", state.Nonce));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);
            _options.Policy.RequireAccessTokenHash = atHashRequired;

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Error validating token response: Invalid access token hash.");
        }

        [Fact]
        public async Task Invalid_signing_algorithm_should_fail()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var key = Crypto.CreateKey();
            var idToken = Crypto.CreateJwt(key, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.ProviderInformation.KeySet = Crypto.CreateKeySet(key);
            _options.BackchannelHandler = new NetworkHandler(JsonConvert.SerializeObject(tokenResponse), HttpStatusCode.OK);

            _options.Policy.ValidSignatureAlgorithms.Clear();
            _options.Policy.ValidSignatureAlgorithms.Add("unsupported");

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("Error validating token response: Identity token uses invalid algorithm: RS256");
        }
    }
}