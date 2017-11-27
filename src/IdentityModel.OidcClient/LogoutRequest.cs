// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;

namespace IdentityModel.OidcClient
{
    public class LogoutRequest
    {
        public DisplayMode BrowserDisplayMode { get; set; } = DisplayMode.Visible;
        public int BrowserTimeout { get; set; } = 300;

        public string IdTokenHint { get; set; }
    }
}