using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel.Client;
using IdentityModel.OidcClient.Results;
using Xunit;

namespace IdentityModel.OidcClient.Tests
{
    public class RefreshTokenDelegatingHandlerTests
    {
        [Fact]
        public async Task Can_refresh_access_tokens_with_sliding_refresh_tokens()
        {
            const int maxCallsPerAccessToken = 2;

            var tokens = new TestTokens(maxCallsPerAccessToken);

            var handlerUnderTest = new RefreshTokenDelegatingHandler(
                new TestableOidcTokenRefreshClient(tokens), tokens.InitialAccessToken, tokens.InitialRefreshToken,
                new TestServer(tokens));

            using (var client = new TestClient(handlerUnderTest))
            {
                tokens.Count.Should().Be(1);
                await client.SecuredPing();
                tokens.Count.Should().Be(1);
                await client.SecuredPing();
                tokens.Count.Should().Be(1);
                await client.SecuredPing();
                tokens.Count.Should().Be(2);
            }
        }

        private class TestClient : IDisposable
        {
            private readonly HttpClient _client;

            public TestClient(RefreshTokenDelegatingHandler refreshTokenHandler)
            {
                _client = new HttpClient(refreshTokenHandler)
                {
                    BaseAddress = new Uri("http://testing")
                };
            }

            public async Task SecuredPing()
            {
                await _client.GetAsync("/whatever");
            }

            public void Dispose()
            {
                _client.Dispose();
            }
        }

        /// <summary>
        /// Simulates access tokens with sliding expiration tokens.
        /// The important bit being that the refresh token gets invalidated after each access token refresh.
        /// Expiration is simulated by counting access token usage instead of time-based expiration. (see <see cref="_maxCallsPerAccessToken"/> and <see cref="TokenSet.AccessTokenUseCount"/>)
        /// </summary>
        private class TestTokens
        {
            private readonly int _maxCallsPerAccessToken;
            private readonly ConcurrentStack<TokenSet> _tokens;

            public TestTokens(int maxCallsPerAccessToken)
            {
                _maxCallsPerAccessToken = maxCallsPerAccessToken;

                var initialTokenSet = new TokenSet();

                InitialAccessToken = initialTokenSet.AccessToken;
                InitialRefreshToken = initialTokenSet.RefreshToken;

                _tokens = new ConcurrentStack<TokenSet>();
                _tokens.Push(initialTokenSet);
            }

            public string InitialAccessToken { get; }
            public string InitialRefreshToken { get; }
            public int Count => _tokens.Count;

            internal class TokenSet
            {
                private int _useCount;
                private static int SequenceNumber;

                public TokenSet()
                {
                    var number = Interlocked.Increment(ref SequenceNumber);

                    AccessToken = $"AT-{number}";
                    RefreshToken = $"RT-{number}";
                }

                public string AccessToken { get; }
                public string RefreshToken { get; }
                public int AccessTokenUseCount => Interlocked.Increment(ref _useCount);
            }

            public bool IsValid(string accessToken)
            {
                if (_tokens.TryPeek(out var currentTokens))
                {
                    if (currentTokens.AccessToken != accessToken)
                        return false;

                    var expired = currentTokens.AccessTokenUseCount > _maxCallsPerAccessToken;

                    return !expired;
                }

                return false;
            }

            internal TokenSet RefreshUsing(string refreshToken)
            {
                if (_tokens.TryPeek(out var currentTokens) && currentTokens.RefreshToken == refreshToken)
                {
                    var newTokens = new TokenSet();
                    _tokens.Push(newTokens);
                    return newTokens;
                }

                return null;
            }
        }

        private class TestServer : DelegatingHandler
        {
            private readonly TestTokens _tokens;

            public TestServer(TestTokens tokens)
            {
                _tokens = tokens;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                var accessToken = request.Headers.Authorization?.Parameter;

                var responseCode = _tokens.IsValid(accessToken)
                    ? HttpStatusCode.OK
                    : HttpStatusCode.Unauthorized;

                return Task.FromResult(new HttpResponseMessage(responseCode));
            }
        }

        private class TestableOidcTokenRefreshClient : OidcClient
        {
            private readonly TestTokens _tokens;

            public TestableOidcTokenRefreshClient(TestTokens tokens) : base(new OidcClientOptions
            {
                Authority = "http://test-authority"
            })
            {
                _tokens = tokens;
            }

            public override Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken,
                Parameters backChannelParameters = null,
                CancellationToken cancellationToken = default)
            {
                var newTokens = _tokens.RefreshUsing(refreshToken);

                RefreshTokenResult result;

                if (newTokens == null)
                    result = new RefreshTokenResult {Error = "something with grant"};
                else
                    result = new RefreshTokenResult
                    {
                        AccessToken = newTokens.AccessToken,
                        RefreshToken = newTokens.RefreshToken
                    };

                return Task.FromResult(result);
            }
        }
    }
}
