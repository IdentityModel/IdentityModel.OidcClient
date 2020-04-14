// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class EndSessionUrlTests
    {
        [Fact]
        public void Default_parameters_should_create_expected_end_session_url()
        {
            var options = new OidcClientOptions();
            var client = new AuthorizeClient(options);

            var url = client.CreateEndSessionUrl("https://server/end_session", new LogoutRequest());

            url.Should().Be("https://server/end_session");
        }

        [Fact]
        public void Post_logout_redirect_parameter_should_create_expected_end_session_url()
        {
            var options = new OidcClientOptions
            {
                PostLogoutRedirectUri = "https://client.com/page"
            };

            var client = new AuthorizeClient(options);
            var url = client.CreateEndSessionUrl("https://server/end_session", new LogoutRequest());

            url.Should().Be("https://server/end_session?post_logout_redirect_uri=https%3A%2F%2Fclient.com%2Fpage");
        }

        [Fact]
        public void Post_logout_redirect_parameter_and_id_token_hint_should_create_expected_end_session_url()
        {
            var options = new OidcClientOptions
            {
                PostLogoutRedirectUri = "https://client.com/page"
            };

            var client = new AuthorizeClient(options);
            var url = client.CreateEndSessionUrl("https://server/end_session", new LogoutRequest { IdTokenHint = "id_token" });

            url.Should().Be("https://server/end_session?id_token_hint=id_token&post_logout_redirect_uri=https%3A%2F%2Fclient.com%2Fpage");
        }

        [Fact]
        public void Id_token_hint_should_create_expected_end_session_url()
        {
            var options = new OidcClientOptions();
            var client = new AuthorizeClient(options);

            var url = client.CreateEndSessionUrl("https://server/end_session", new LogoutRequest { IdTokenHint = "id_token" });

            url.Should().Be("https://server/end_session?id_token_hint=id_token");
        }
    }
}