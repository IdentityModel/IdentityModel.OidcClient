using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.DPoP
{
    public class ProofTokenMessageHandler : DelegatingHandler
    {
        private readonly ProofToken _proofToken;
        
        public ProofTokenMessageHandler(JsonWebKey key, HttpMessageHandler innerHandler)
        {
            _proofToken = new ProofToken(key);
            InnerHandler = innerHandler ?? throw new ArgumentNullException(nameof(innerHandler));
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var token = _proofToken.CreateToken(request);
            request.Headers.Add(OidcConstants.HttpHeaders.DPoP, token);

            return base.SendAsync(request, cancellationToken);
        }
    }
}