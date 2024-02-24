// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityModel.OidcClient.DPoP;

/// <summary>
/// Models a DPoP proof token
/// </summary>
public class DPoPProof
{
    /// <summary>
    /// The proof token
    /// </summary>
    public string ProofToken { get; set; } = default!;
}
