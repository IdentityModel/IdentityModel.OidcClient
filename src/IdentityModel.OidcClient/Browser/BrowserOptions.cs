// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IdentityModel.OidcClient.Browser
{
    public class BrowserOptions
    {
        public string StartUrl { get; }
        public string EndUrl { get; }

        public OidcClientOptions.AuthorizeResponseMode ResponseMode { get; set; } = OidcClientOptions.AuthorizeResponseMode.FormPost;
        public DisplayMode DisplayMode { get; set; } = DisplayMode.Visible;
        public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);

        public BrowserOptions(string startUrl, string endUrl)
        {
            StartUrl = startUrl;
            EndUrl = endUrl;
        }
    }
}