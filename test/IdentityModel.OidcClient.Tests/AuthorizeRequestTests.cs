using FluentAssertions;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class AuthorizeRequestTests
    {
        [Fact]
        public void default_parameters_should_be_used_for_authorize_request()
        {
            var options = new OidcClientOptions
            {
                ClientId = "client_id",
                Scope = "openid",
                RedirectUri = "http://redirect",

                ResponseMode = OidcClientOptions.AuthorizeResponseMode.FormPost,
                Flow = OidcClientOptions.AuthenticationFlow.Hybrid
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateParameters("state", "nonce", "code_challenge", null);

            parameters.Should().Contain("client_id", "client_id");
            parameters.Should().Contain("scope", "openid");
            parameters.Should().Contain("redirect_uri", "http://redirect");

            parameters.Should().Contain("response_type", "code id_token");
            parameters.Should().Contain("response_mode", "form_post");

            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }

        [Fact]
        public void extra_parameters_should_override_default_parameters()
        {
            var options = new OidcClientOptions
            {
                ClientId = "client_id",
                Scope = "openid",
                RedirectUri = "http://redirect",

                ResponseMode = OidcClientOptions.AuthorizeResponseMode.FormPost,
                Flow = OidcClientOptions.AuthenticationFlow.Hybrid
            };

            var extra = new
            {
                client_id = "client_id2",
                scope = "openid extra",
                redirect_uri = "http://redirect2"
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateParameters("state", "nonce", "code_challenge", extra);

            parameters.Should().Contain("client_id", "client_id2");
            parameters.Should().Contain("scope", "openid extra");
            parameters.Should().Contain("redirect_uri", "http://redirect2");

            parameters.Should().Contain("response_type", "code id_token");
            parameters.Should().Contain("response_mode", "form_post");

            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }

        [Fact]
        public void missing_default_parameters_can_be_set_by_extra_parameters()
        {
            var options = new OidcClientOptions
            {
                ResponseMode = OidcClientOptions.AuthorizeResponseMode.FormPost,
                Flow = OidcClientOptions.AuthenticationFlow.Hybrid
            };

            var extra = new
            {
                client_id = "client_id2",
                scope = "openid extra",
                redirect_uri = "http://redirect2"
            };

            var client = new AuthorizeClient(options);
            var parameters = client.CreateParameters("state", "nonce", "code_challenge", extra);

            parameters.Should().Contain("client_id", "client_id2");
            parameters.Should().Contain("scope", "openid extra");
            parameters.Should().Contain("redirect_uri", "http://redirect2");

            parameters.Should().Contain("response_type", "code id_token");
            parameters.Should().Contain("response_mode", "form_post");

            parameters.Should().Contain("state", "state");
            parameters.Should().Contain("nonce", "nonce");
            parameters.Should().Contain("code_challenge", "code_challenge");
        }
    }
}