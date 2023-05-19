// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net;
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
    private string? _nonce;
    private HttpStatusCode _retryStatusCode = HttpStatusCode.Unauthorized;

    /// <summary>
    /// Constructor
    /// </summary>
    public ProofTokenMessageHandler(string proofKey, HttpMessageHandler innerHandler)
    {
        _proofTokenFactory = new DPoPProofTokenFactory(proofKey);
        InnerHandler = innerHandler ?? throw new ArgumentNullException(nameof(innerHandler));
    }

    /// <summary>
    /// Constructor that allows controlling upon which HTTP status code to retry with the DPoP nonce.
    /// </summary>
    protected ProofTokenMessageHandler(string proofKey, HttpMessageHandler innerHandler, HttpStatusCode retryStatusCode) : this(proofKey, innerHandler)
    {
        _retryStatusCode = retryStatusCode;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CreateProofToken(request);

        var response = await base.SendAsync(request, cancellationToken);

        var dPoPNonce = response.GetDPoPNonce();

        if (dPoPNonce != null)
        {
            _nonce = dPoPNonce;

            // retry?
            if (response.StatusCode == _retryStatusCode)
            {
                response.Dispose();

                CreateProofToken(request);
                response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }

        return response;
    }

    private void CreateProofToken(HttpRequestMessage request)
    {
        var proofRequest = new DPoPProofRequest
        {
            Method = request.Method.ToString(),
            Url = request.GetDPoPUrl(),
            DPoPNonce = _nonce
        };

        if (request.Headers.Authorization != null &&
            OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer.Equals(request.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            proofRequest.AccessToken = request.Headers.Authorization.Parameter;
        }

        var proof = _proofTokenFactory.CreateProofToken(proofRequest);

        request.SetDPoPProofToken(proof.ProofToken);
    }
}