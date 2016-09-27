// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IdentityModel.OidcClient.WebView
{
    public class InvokeOptions
    {
        public string StartUrl { get; }
        public string EndUrl { get; }

        public ResponseMode ResponseMode { get; set; } = ResponseMode.Redirect;
        public DisplayMode InitialDisplayMode { get; set; } = DisplayMode.Visible;
        public TimeSpan InvisibleModeTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public InvokeOptions(string startUrl, string endUrl)
        {
            StartUrl = startUrl;
            EndUrl = endUrl;
        }
    }
}