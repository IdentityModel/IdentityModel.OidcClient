// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient
{
    public class AuthorizeResult
    {
        public bool Success { get; set; }
        public string Error { get; set; }

        public string Data { get; set; }
        public AuthorizeState State { get; set; }
    }
}