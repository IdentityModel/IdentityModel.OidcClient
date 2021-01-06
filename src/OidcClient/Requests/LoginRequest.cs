// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;
using IdentityModel.Client;

namespace IdentityModel.OidcClient
{
    public class FrontChannelParameters
    {
        public ICollection<string> Resource { get; set; } = new HashSet<string>();
        public Parameters Extra { get; set; } = new Parameters();
    }

    public class BackChannelParameters
    {
        public Parameters Extra { get; set; } = new Parameters();
    }
    
    /// <summary>
    /// A login request.
    /// </summary>
    public class LoginRequest
    {
        /// <summary>
        /// Gets or sets the browser display mode.
        /// </summary>
        /// <value>
        /// The browser display mode.
        /// </value>
        public DisplayMode BrowserDisplayMode { get; set; } = DisplayMode.Visible;

        /// <summary>
        /// Gets or sets the browser timeout.
        /// </summary>
        /// <value>
        /// The browser timeout.
        /// </value>
        public int BrowserTimeout { get; set; } = 300;

        
        public FrontChannelParameters FrontChannel { get; set; } = new FrontChannelParameters();
        public BackChannelParameters BackChannel { get; set; } = new BackChannelParameters();
    }
}