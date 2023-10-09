using System.Net.Http;

namespace IdentityModel.OidcClient.DPoP;

public static class OidcClientExtensions
{
    public static void ConfigureDPoP(this OidcClientOptions options, 
        string proofKey,
        HttpMessageHandler? tokenEndpointInnerHandler = null,
        HttpMessageHandler? apiInnerHandler = null)
    {
        var tokenDpopHandler = new ProofTokenMessageHandler(proofKey, tokenEndpointInnerHandler ?? new HttpClientHandler());
        var apiDpopHandler = new ProofTokenMessageHandler(proofKey, apiInnerHandler ?? new HttpClientHandler());
        
        options.BackchannelHandler = tokenDpopHandler;
        options.RefreshTokenInnerHttpHandler = apiDpopHandler;
    }

    public static HttpMessageHandler CreateDPoPHandler(this OidcClient client, 
        string proofKey, 
        string refreshToken, 
        HttpMessageHandler? apiInnerHandler = null)
    {
        var apiDpopHandler = new ProofTokenMessageHandler(proofKey, apiInnerHandler ?? new HttpClientHandler());
        
        var handler = new RefreshTokenDelegatingHandler(
            client, 
            null, 
            refreshToken, 
            "DPoP",
            apiDpopHandler);

        return handler;
    }
}