// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FluentAssertions;
using IdentityModel.Jwk;
using IdentityModel.OidcClient.Tests.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel.Client;
using Xunit;
using System.Web;

namespace IdentityModel.OidcClient.Tests
{
    public class CodeFlowResponseTestsWithNoValidation
    {
        private readonly OidcClientOptions _options = new OidcClientOptions
        {
            ClientId = "client",
            Scope = "openid profile api",
            RedirectUri = "https://redirect",

            LoadProfile = false,

            Policy = new Policy
            {
                RequireIdentityTokenSignature = false,

                Discovery = new DiscoveryPolicy
                {
                    RequireKeySet = false
                }
            },


            ProviderInformation = new ProviderInformation
            {
                IssuerName = "https://authority",
                AuthorizeEndpoint = "https://authority/authorize",
                TokenEndpoint = "https://authority/token",
                UserInfoEndpoint = "https://authority/userinfo"
            }
        };

        [Fact]
        public async Task Valid_response_with_id_token_should_succeed()
        {
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"),
                new Claim("auth_time", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();
            result.AuthenticationTime.Should().Be(DateTimeOffset.FromUnixTimeSeconds(123));

            result.User.Claims.Count().Should().Be(1);
            result.User.Claims.First().Type.Should().Be("sub");
            result.User.Claims.First().Value.Should().Be("123");
        }

        [Fact]
        public async Task Valid_response_without_id_token_should_succeed()
        {
            _options.Scope = "api";
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().BeNull();
            result.User.Identity.IsAuthenticated.Should().BeFalse();
        }

        [Fact]
        public async Task Valid_response_with_profile_should_succeed()
        {
            _options.LoadProfile = true;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

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

            var networkHandler = new NetworkHandler(request =>
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("token"))
                {
                    return JsonSerializer.Serialize(tokenResponse);
                }
                else if (request.RequestUri.AbsoluteUri.EndsWith("userinfo"))
                {
                    return JsonSerializer.Serialize(userinfoResponse);
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

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            var backChannelHandler = new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = backChannelHandler;

            var result = await client.ProcessResponseAsync(url, state);

            var request = backChannelHandler.Request;

            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Scheme.Should().Be("Basic");
            request.Headers.Authorization.Parameter.Should()
                .Be(BasicAuthenticationOAuthHeaderValue.EncodeCredential("client", "secret"));
        }

        [Fact]
        public async Task Sending_client_credentials_in_body_should_succeed()
        {
            _options.ClientSecret = "secret";
            _options.TokenClientCredentialStyle = Client.ClientCredentialStyle.PostBody;

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            var backChannelHandler = new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);
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

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://{some_multi_tenant_name}", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

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

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            var handler = new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = handler;

            var backChannel = new Parameters
            {
                { "foo", "foo" },
                { "bar", "bar" }
            };

            var result = await client.ProcessResponseAsync(url, state, backChannel);

            result.IsError.Should().BeFalse();
            result.AccessToken.Should().Be("token");
            result.IdentityToken.Should().NotBeNull();
            result.User.Should().NotBeNull();

            var body = handler.Body;
            body.Should().Contain("foo=foo");
            body.Should().Contain("bar=bar");
        }

        [Fact]
        public async Task No_identity_token_validator_should_fail()
        {
            _options.Policy.RequireIdentityTokenSignature = true;
            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

            var tokenResponse = new Dictionary<string, object>
            {
                { "access_token", "token" },
                { "expires_in", 300 },
                { "id_token", idToken },
                { "refresh_token", "refresh_token" }
            };

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

            Func<Task> act = async () => { await client.ProcessResponseAsync(url, state); };
            act.Should().Throw<InvalidOperationException>()
                .Where(e => e.Message.StartsWith("No IIdentityTokenValidator is configured"));
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

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

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

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

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

            var url = $"?state={state.State}&code=bar";
            var idToken = Crypto.CreateJwt(null, "https://authority", "client",
                new Claim("at_hash", Crypto.HashData("token")),
                new Claim("sub", "123"));

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

            var networkHandler = new NetworkHandler(request =>
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("token"))
                {
                    return JsonSerializer.Serialize(tokenResponse);
                }
                else if (request.RequestUri.AbsoluteUri.EndsWith("userinfo"))
                {
                    return JsonSerializer.Serialize(userinfoResponse);
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

            _options.BackchannelHandler =
                new NetworkHandler(JsonSerializer.Serialize(tokenResponse), HttpStatusCode.OK);

            var client = new OidcClient(_options);
            var state = await client.PrepareLoginAsync();

            var url = $"?state={state.State}&code=bar";
            var result = await client.ProcessResponseAsync(url, state);

            result.IsError.Should().BeTrue();
            result.Error.Should().Contain("invalid_jwt");
        }

        [Fact]
        public async Task Authorize_should_push_parameters_when_PAR_is_enabled()
        {
            // Configure the client for PAR, authenticating with a client secret
            _options.ClientSecret = "secret";
            _options.ProviderInformation.PushedAuthorizationRequestEndpoint = "https://this-is-set-so-par-will-be-used";
            var client = new OidcClient(_options);

            // Mock the response from the par endpoint
            var requestUri = "mocked_request_uri";
            var parResponse = new Dictionary<string, string>
            {
                { "request_uri", requestUri }
            };
            var backChannelHandler = new NetworkHandler(JsonSerializer.Serialize(parResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = backChannelHandler;

            // Prepare the login to cause the backchannel PAR request
            var state = await client.PrepareLoginAsync();

            // Validate that the resulting PAR state is correct
            var startUrl = new Uri(state.StartUrl);
            var startUrlQueryParams = HttpUtility.ParseQueryString(startUrl.Query);
            startUrlQueryParams.Should().HaveCount(2);
            startUrlQueryParams.GetValues("client_id").Single().Should().Be("client");
            startUrlQueryParams.GetValues("request_uri").Single().Should().Be(requestUri);

            // Validate that the client authentication during the PAR request was correct
            var request = backChannelHandler.Request;
            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Scheme.Should().Be("Basic");
            request.Headers.Authorization.Parameter.Should()
                .Be(BasicAuthenticationOAuthHeaderValue.EncodeCredential("client", "secret"));
        }
        
        [Fact]
        public async Task Par_request_should_include_client_assertion_in_body()
        {
            // Configure the client for PAR, authenticating with a client assertion
            var clientAssertion = "mocked_client_assertion";
            var clientAssertionType = "mocked_assertion_type";
            _options.ClientAssertion = new ClientAssertion
            {
                Type = clientAssertionType,
                Value = clientAssertion
            };
            _options.ProviderInformation.PushedAuthorizationRequestEndpoint = "https://this-is-set-so-par-will-be-used";
            var client = new OidcClient(_options);

            // Mock the response from the par endpoint
            var requestUri = "mocked_request_uri";
            var parResponse = new Dictionary<string, string>
            {
                { "request_uri", requestUri }
            };
            var backChannelHandler = new NetworkHandler(JsonSerializer.Serialize(parResponse), HttpStatusCode.OK);
            _options.BackchannelHandler = backChannelHandler;

            // Prepare the login to cause the backchannel PAR request
            var state = await client.PrepareLoginAsync();

            // Validate that the resulting PAR state is correct
            var startUrl = new Uri(state.StartUrl);
            var startUrlQueryParams = HttpUtility.ParseQueryString(startUrl.Query);
            startUrlQueryParams.Should().HaveCount(2);
            startUrlQueryParams.GetValues("client_id").Single().Should().Be("client");
            startUrlQueryParams.GetValues("request_uri").Single().Should().Be(requestUri);

            // Validate that the client authentication during the PAR request was correct
            var parRequest = backChannelHandler.Request;
            var parContent = await parRequest.Content.ReadAsStringAsync();
            var parParams = HttpUtility.ParseQueryString(parContent);
            parParams.GetValues("client_assertion").Single().Should().Be(clientAssertion);
            parParams.GetValues("client_assertion_type").Single().Should().Be(clientAssertionType);
            parRequest.Headers.Authorization.Should().BeNull();
        }
    }
}