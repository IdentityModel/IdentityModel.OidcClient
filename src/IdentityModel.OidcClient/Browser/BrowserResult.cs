// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient.Browser
{
    public class BrowserResult : Result
    {
        public BrowserResultType ResultType { get; set; }
        public string Response { get; set; }
    }
}