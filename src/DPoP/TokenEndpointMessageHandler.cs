// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Http;

namespace IdentityModel.DPoP;

/// <summary>
/// Message handler to create and send DPoP proof tokens.
/// </summary>
public class TokenEndpointMessageHandler : ProofTokenMessageHandler
{
    /// <summary>
    /// Constructor
    /// </summary>
    public TokenEndpointMessageHandler(string proofKey, HttpMessageHandler innerHandler)
        : base(proofKey, innerHandler, HttpStatusCode.BadRequest)
    {
    }
}