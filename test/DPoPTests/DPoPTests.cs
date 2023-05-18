
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityModel.DPoP;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Xunit;

namespace DPoPTests;

public class DPoPTest : IntegrationTestBase
{
    private static readonly string _jwkJson;

    static DPoPTest()
    {
        var key = CryptoHelper.CreateRsaSecurityKey();
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = "RS256";
        _jwkJson = JsonSerializer.Serialize(jwk);
    }

    public DPoPTest()
    {
        IdentityServerHost.ApiScopes.Add(new ApiScope("scope1"));

        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "client_credentials_client",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes = { "scope1" },
            RequireDPoP = true,
        });
    }

    [Fact]
    public async Task dpop_tokens_should_be_passed_to_token_endpoint()
    {
        var handler = new ProofTokenMessageHandler(_jwkJson, IdentityServerHost.Server.CreateHandler());
        var client = new HttpClient(handler);
        
        var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = IdentityServerHost.Url("/connect/token"),
            ClientId = "client_credentials_client",
            ClientSecret = "secret",
        });

        tokenResponse.HttpStatusCode.Should().Be(HttpStatusCode.OK);
        tokenResponse.TokenType.Should().Be("DPoP");
    }

    [Fact]
    public async Task dpop_tokens_should_be_passed_to_api()
    {
        var tokenHandler = new ProofTokenMessageHandler(_jwkJson, IdentityServerHost.Server.CreateHandler());
        var tokenClient = new HttpClient(tokenHandler);

        var tokenResponse = await tokenClient.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = IdentityServerHost.Url("/connect/token"),
            ClientId = "client_credentials_client",
            ClientSecret = "secret",
        });

        var apiHandler = new ProofTokenMessageHandler(_jwkJson, ApiHost.Server.CreateHandler());
        var apiClient = new HttpClient(apiHandler);
        apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("DPoP", tokenResponse.AccessToken);

        ApiHost.ApiInvoked += ctx =>
        {
            ctx.User.Identity.IsAuthenticated.Should().BeTrue();
        };

        var apiResponse = await apiClient.GetAsync(ApiHost.Url("/api"));
        apiResponse.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}