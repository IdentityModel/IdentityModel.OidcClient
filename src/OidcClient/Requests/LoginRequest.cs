// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;
using IdentityModel.Client;

namespace IdentityModel.OidcClient
{
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

        /// <summary>
        /// Gets or sets the front channel extra parameters.
        /// </summary>
        /// <value>
        /// The front channel extra parameters.
        /// </value>
        public Parameters FrontChannelExtraParameters { get; set; } = new Parameters();

        /// <summary>
        /// Gets or sets the back channel extra parameters.
        /// </summary>
        /// <value>
        /// The back channel extra parameters.
        /// </value>
        public Parameters BackChannelExtraParameters { get; set; } = new Parameters();
    }
}