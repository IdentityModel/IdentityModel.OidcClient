// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Http;

namespace IdentityModel.OidcClient.DPoP;

/// <summary>
/// Extension methods to configure DPoP
/// </summary>
public static class OidcClientExtensions
{
    /// <summary>
    /// Configure back-channel handlers for DPoP
    /// </summary>
    /// <param name="options">The OidcClient options</param>
    /// <param name="proofKey">The proof key</param>
    /// <param name="tokenEndpointInnerHandler">The inner handler for the token endpoint (optional)</param>
    /// <param name="apiInnerHandler">The inner handler for API calls (optional)</param>
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

    /// <summary>
    /// Creates a handler for API calls using DPoP and automatic refresh token management
    /// </summary>
    /// <param name="client">The OidcClient instance</param>
    /// <param name="proofKey">The proof key</param>
    /// <param name="refreshToken">The refresh token</param>
    /// <param name="apiInnerHandler">The inner handler (optional)</param>
    /// <returns></returns>
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