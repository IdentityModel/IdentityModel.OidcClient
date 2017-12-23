// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Net.Http;
using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// The result of a login.
    /// </summary>
    /// <seealso cref="IdentityModel.OidcClient.Result" />
    public class LoginResult : Result
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LoginResult"/> class.
        /// </summary>
        public LoginResult()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LoginResult"/> class.
        /// </summary>
        /// <param name="error">The error.</param>
        public LoginResult(string error)
        {
            Error = error;
        }

        /// <summary>
        /// Gets or sets the user.
        /// </summary>
        /// <value>
        /// The user.
        /// </value>
        public ClaimsPrincipal User { get; internal set; }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        /// <value>
        /// The access token.
        /// </value>
        public string AccessToken { get; internal set; }

        /// <summary>
        /// Gets or sets the identity token.
        /// </summary>
        /// <value>
        /// The identity token.
        /// </value>
        public string IdentityToken { get; internal set; }

        /// <summary>
        /// Gets or sets the refresh token.
        /// </summary>
        /// <value>
        /// The refresh token.
        /// </value>
        public string RefreshToken { get; internal set; }

        /// <summary>
        /// Gets or sets the access token expiration.
        /// </summary>
        /// <value>
        /// The access token expiration.
        /// </value>
        public DateTime AccessTokenExpiration { get; internal set; }

        /// <summary>
        /// Gets or sets the authentication time.
        /// </summary>
        /// <value>
        /// The authentication time.
        /// </value>
        public DateTime AuthenticationTime { get; internal set; }

        /// <summary>
        /// Gets or sets the refresh token handler.
        /// </summary>
        /// <value>
        /// The refresh token handler.
        /// </value>
        public HttpMessageHandler RefreshTokenHandler { get; internal set; }
    }
}