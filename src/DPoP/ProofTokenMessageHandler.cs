// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.DPoP;

/// <summary>
/// Message handler to create and send DPoP proof tokens.
/// </summary>
public class ProofTokenMessageHandler : DelegatingHandler
{
    private readonly DPoPProofTokenFactory _proofTokenFactory;
    
    /// <summary>
    /// Constructor
    /// </summary>
    public ProofTokenMessageHandler(string proofKey, HttpMessageHandler innerHandler)
    {
        _proofTokenFactory = new DPoPProofTokenFactory(proofKey);
        InnerHandler = innerHandler ?? throw new ArgumentNullException(nameof(innerHandler));
    }

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var proofRequest = new DPoPProofRequest
        {
            Method = request.Method.ToString(),
            Url = request.RequestUri.Scheme + "://" + request.RequestUri.Authority + request.RequestUri.AbsolutePath,
        };

        if (request.Headers.Authorization != null &&
            OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer.Equals(request.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            proofRequest.AccessToken = request.Headers.Authorization.Parameter;
        }

        var proof = _proofTokenFactory.CreateProofToken(proofRequest);
        request.Headers.Add(OidcConstants.HttpHeaders.DPoP, proof.ProofToken);

        return base.SendAsync(request, cancellationToken);
    }
}