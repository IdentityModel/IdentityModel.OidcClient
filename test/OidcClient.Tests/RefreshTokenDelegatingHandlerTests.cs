using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using FluentAssertions.Extensions;
using IdentityModel.Client;
using IdentityModel.OidcClient.Results;
using Xunit;
using Xunit.Abstractions;

namespace IdentityModel.OidcClient.Tests
{
    public class RefreshTokenDelegatingHandlerTests
    {
        private readonly Action<string> _writeLine;

        public RefreshTokenDelegatingHandlerTests(ITestOutputHelper output)
        {
            _writeLine = output.WriteLine;
        }

        //private void WriteLine(string message) => _writeLine(message);

        [Fact]
        public async Task Can_refresh_access_tokens_with_sliding_refresh_tokens()
        {
            const int maxCallsPerAccessToken = 2;

            var tokens = new TestTokens(maxCallsPerAccessToken, _writeLine);

            var handlerUnderTest = new RefreshTokenDelegatingHandler(
                new TestableOidcTokenRefreshClient(tokens, TimeSpan.Zero), 
                tokens.InitialAccessToken, 
                tokens.InitialRefreshToken,
                new TestServer(tokens, TimeSpan.Zero));

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

        [Fact]
        public async Task Can_refresh_access_tokens_in_parallel()
        {
            var logicalThreadCount = 10;
            var callsPerThread = 10;
            var maxCallsPerAccessToken = 20;

            var tokens = new TestTokens(maxCallsPerAccessToken);

            var handlerUnderTest = new RefreshTokenDelegatingHandler(
                new TestableOidcTokenRefreshClient(tokens, 5.Milliseconds()),
                tokens.InitialAccessToken,
                tokens.InitialRefreshToken,
                new TestServer(tokens, 1.Milliseconds()));

            using (var client = new TestClient(handlerUnderTest))
            {
                async Task PerformPingRequests()
                {
                    for (var i = 0; i < callsPerThread; i++)
                        await client.SecuredPing();
                }

                var tasks = Enumerable.Range(0, logicalThreadCount).Select(i => PerformPingRequests());

                await Task.WhenAll(tasks);
            }

            tokens.Count.Should().BeGreaterThan(logicalThreadCount * callsPerThread / maxCallsPerAccessToken);
        }

        [Fact]
        public async Task Can_refresh_access_tokens_in_parallel_using_non_singleton_handler()
        {
            RefreshTokenDelegatingHandler CreateHandler(TestTokens testTokens)
            {
                return new RefreshTokenDelegatingHandler(
                    new TestableOidcTokenRefreshClient(testTokens, 20.Milliseconds()),
                    testTokens.InitialAccessToken,
                    testTokens.InitialRefreshToken,
                    new TestServer(testTokens, 0.Milliseconds()));
            }

            var logicalThreadCount = 2;
            var callsPerThread = 20;
            var maxCallsPerAccessToken = 10;

            var tokens = new TestTokens(maxCallsPerAccessToken, _writeLine);

            async Task PerformPingRequests()
            {
                using (var client = new TestClient(CreateHandler(tokens)))
                    for (var i = 0; i < callsPerThread; i++)
                        await client.SecuredPing();
            }

            var tasks = Enumerable.Range(0, logicalThreadCount).Select(i => PerformPingRequests());

            await Task.WhenAll(tasks);

            tokens.Count.Should().BeGreaterThan(logicalThreadCount * callsPerThread / maxCallsPerAccessToken);
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
                var response = await _client.GetAsync("/whatever");
                response.EnsureSuccessStatusCode();
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
            private readonly Action<string> _writeLine;
            private readonly ConcurrentStack<TokenSet> _tokens;

            public TestTokens(int maxCallsPerAccessToken, Action<string> writeLine = null)
            {
                _maxCallsPerAccessToken = maxCallsPerAccessToken;
                _writeLine = writeLine;

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
                    {
                        _writeLine?.Invoke($"{accessToken} is no longer valid because it has been superseded");
                        return false;
                    }

                    var useCount = currentTokens.AccessTokenUseCount;
                    var expired = useCount > _maxCallsPerAccessToken;

                    if (expired)
                        _writeLine?.Invoke($"{accessToken} is no longer valid because it has been used {useCount} times (more than the {_maxCallsPerAccessToken} allowed)");
                    else
                        _writeLine?.Invoke($"{accessToken} is still valid (used {useCount} times now)");

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
            private readonly TimeSpan _pingDelay;

            public TestServer(TestTokens tokens, TimeSpan pingDelay)
            {
                _tokens = tokens;
                _pingDelay = pingDelay;
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                var accessToken = request.Headers.Authorization?.Parameter;

                var responseCode = _tokens.IsValid(accessToken)
                    ? HttpStatusCode.OK
                    : HttpStatusCode.Unauthorized;

                await Task.Delay(_pingDelay, cancellationToken);

                return new HttpResponseMessage(responseCode);
            }
        }

        private class TestableOidcTokenRefreshClient : OidcClient
        {
            private readonly TestTokens _tokens;
            private readonly TimeSpan _delayForRefresh;

            public TestableOidcTokenRefreshClient(TestTokens tokens, TimeSpan delayForRefresh) : base(new OidcClientOptions
            {
                Authority = "http://test-authority"
            })
            {
                _tokens = tokens;
                _delayForRefresh = delayForRefresh;
            }

            public override async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken,
                Parameters backChannelParameters = null,
                CancellationToken cancellationToken = default)
            {
                var newTokens = _tokens.RefreshUsing(refreshToken);

                await Task.Delay(_delayForRefresh, cancellationToken);

                return newTokens == null
                    ? new RefreshTokenResult {Error = "something with grant"}
                    : new RefreshTokenResult
                    {
                        AccessToken = newTokens.AccessToken,
                        RefreshToken = newTokens.RefreshToken
                    };
            }
        }
    }
}
