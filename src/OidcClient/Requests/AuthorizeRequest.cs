// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    class AuthorizeRequest
    {
        public DisplayMode DisplayMode { get; set; } = DisplayMode.Visible;
        public int Timeout { get; set; } = 300;
        public IDictionary<string, string> ExtraParameters = new Dictionary<string, string>();
    }
}