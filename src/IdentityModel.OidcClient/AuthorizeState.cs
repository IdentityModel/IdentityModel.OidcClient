// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient
{
    public class AuthorizeState
    {
        public string Nonce { get; set; }
        public string State { get; set; } 
        public string CodeVerifier { get; set; }

        public string StartUrl { get; set; }
        public string RedirectUri { get; set; }
    }
}