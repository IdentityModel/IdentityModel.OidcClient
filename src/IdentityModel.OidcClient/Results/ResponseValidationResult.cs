// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    internal class ResponseValidationResult : Result
    {
        public ResponseValidationResult()
        {

        }

        public ResponseValidationResult(string error)
        {
            Error = error;
        }

        public AuthorizeResponse AuthorizeResponse { get; set; }
        public TokenResponse TokenResponse { get; set; }
        public ClaimsPrincipal User { get; set; }
    }
}