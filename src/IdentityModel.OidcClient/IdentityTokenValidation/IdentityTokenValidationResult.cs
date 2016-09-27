// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    public class IdentityTokenValidationResult
    {
        public bool Success { get; set; }
        public string Error { get; set; }
        public ClaimsPrincipal User { get; set; }
        public string SignatureAlgorithm { get; set; }
    }
}