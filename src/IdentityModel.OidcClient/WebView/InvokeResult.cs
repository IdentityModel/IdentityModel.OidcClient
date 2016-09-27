// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityModel.OidcClient.WebView
{
    public class InvokeResult
    {
        public InvokeResultType ResultType { get; set; }
        public string Response { get; set; }
        public string Error { get; set; }
    }
}