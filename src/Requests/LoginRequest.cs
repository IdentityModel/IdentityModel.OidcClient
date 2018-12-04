// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;

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
        public IDictionary<string, string> FrontChannelExtraParameters { get; set; }

        /// <summary>
        /// Gets or sets the back channel extra parameters.
        /// </summary>
        /// <value>
        /// The back channel extra parameters.
        /// </value>
        public IDictionary<string, string> BackChannelExtraParameters { get; set; }
    }
}