// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Jwk;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// Information about a ProofOfPossession Key
    /// </summary>
    public class ProofOfPossession
    {
        /// <summary>
        /// Gets or sets the Key to use for proving possession of tokens
        /// </summary>
        public JsonWebKey Key { get; set; }

        /// <summary>
        /// Gets the string version of the Key
        /// </summary>
        public string JwkString => Key?.ToJwkString();

        /// <summary>
        /// Gets the algorithm used to create the Key
        /// </summary>
        public string Algorithm => Key?.Alg;
    }
}