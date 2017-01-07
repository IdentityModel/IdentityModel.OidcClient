using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class Spike
    {
        [Fact]
        public async Task Test()
        {
            var options = new OidcClientOptions
            {
                Authority = "https://demo.identityserver.io",

                ClientId = "client",
                RedirectUri = "myapp://callback",
                Scope = "openid api"
            };

            var client = new OidcClient(options);
            var state = await client.PrepareLoginAsync();

            state.Should().NotBeNull();
        }
    }
}
