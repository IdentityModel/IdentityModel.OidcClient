// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;
using IdentityModel.Client;
using System;

namespace IdentityModel.OidcClient
{
    class AuthorizeRequest
    {
        [Obsolete]
        public DisplayMode DisplayMode { get; set; } = DisplayMode.Visible;
        [Obsolete]
        public int Timeout { get; set; } = 300;
        
        public Parameters ExtraParameters = new Parameters();
    }
}