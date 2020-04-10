// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class AuthorizeRequestTests
    {
        [Fact]
        public void Default_parameters_should_be_used_for_authorize_request()
        {
            var options = new OidcClientOptions
            {
                ClientId = "client_id",
                Scope = "openid",
                RedirectUri = "http://redirect"
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateAuthorizeParameters("state", "nonce", "code_challenge", null);

            parameters.Should().Contain("client_id", "client_id");
            parameters.Should().Contain("scope", "openid");
            parameters.Should().Contain("redirect_uri", "http://redirect");
            parameters.Should().Contain("response_type", "code");
            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }

        [Fact]
        public void Extra_parameters_should_override_default_parameters()
        {
            var options = new OidcClientOptions
            {
                ClientId = "client_id",
                Scope = "openid",
                RedirectUri = "http://redirect"
            };

            var extra = new Dictionary<string, string>
            {
                { "client_id", "client_id2" },
                { "scope", "openid extra" },
                { "redirect_uri", "http://redirect2" }
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateAuthorizeParameters("state", "nonce", "code_challenge", extra);

            parameters.Should().Contain("client_id", "client_id2");
            parameters.Should().Contain("scope", "openid extra");
            parameters.Should().Contain("redirect_uri", "http://redirect2");
            parameters.Should().Contain("response_type", "code");
            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }

        [Fact]
        public void Missing_default_parameters_can_be_set_by_extra_parameters()
        {
            var options = new OidcClientOptions();

            var extra = new Dictionary<string, string>
            {
                { "client_id", "client_id2" },
                { "scope", "openid extra" },
                { "redirect_uri", "http://redirect2" }
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateAuthorizeParameters("state", "nonce", "code_challenge", extra);

            parameters.Should().Contain("client_id", "client_id2");
            parameters.Should().Contain("scope", "openid extra");
            parameters.Should().Contain("redirect_uri", "http://redirect2");
            parameters.Should().Contain("response_type", "code");
            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }

        [Fact]
        public async Task Browser_error_is_surfaced_in_authorize_response()
        {
            var options = new OidcClientOptions
            {
                ClientId = "client_id",
                Scope = "openid",
                RedirectUri = "http://redirect",
                ProviderInformation = new ProviderInformation
                {
                    AuthorizeEndpoint = "https://authority/authorize"
                },

                Browser = new TestBrowser(_ => Task.FromResult(new BrowserResult
                {
                    ResultType = BrowserResultType.HttpError,
                    Error = "Something terrible happened"
                }))
            };

            var client = new AuthorizeClient(options);

            var response = await client.AuthorizeAsync(new AuthorizeRequest());

            response.Error.Should().Be("Something terrible happened");
        }
    }
}