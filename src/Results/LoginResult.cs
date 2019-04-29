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
        public virtual ClaimsPrincipal User { get; internal set; }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        /// <value>
        /// The access token.
        /// </value>
        public virtual string AccessToken { get; internal set; }

        /// <summary>
        /// Gets or sets the identity token.
        /// </summary>
        /// <value>
        /// The identity token.
        /// </value>
        public virtual string IdentityToken { get; internal set; }

        /// <summary>
        /// Gets or sets the refresh token.
        /// </summary>
        /// <value>
        /// The refresh token.
        /// </value>
        public virtual string RefreshToken { get; internal set; }

        /// <summary>
        /// Gets or sets the access token expiration.
        /// </summary>
        /// <value>
        /// The access token expiration.
        /// </value>
        public virtual DateTime AccessTokenExpiration { get; internal set; }

        /// <summary>
        /// Gets or sets the authentication time.
        /// </summary>
        /// <value>
        /// The authentication time.
        /// </value>
        public virtual DateTime AuthenticationTime { get; internal set; }

        /// <summary>
        /// Gets or sets the refresh token handler.
        /// </summary>
        /// <value>
        /// The refresh token handler.
        /// </value>
        public virtual DelegatingHandler RefreshTokenHandler { get; internal set; }
    }
}