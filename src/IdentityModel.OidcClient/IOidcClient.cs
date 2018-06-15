// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Results;
using System;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient {
    /// <summary>
    /// OpenID Connect client
    /// </summary>
    interface IOidcClient {

        /// <summary>
        /// Starts a login.
        /// </summary>
        /// <param name="displayMode">The browser display mode.</param>
        /// <param name="timeout">The browser timeout.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns></returns>
        [Obsolete("This method will be removed in a future version. Please change your code to use LoginRequest")]
        Task<LoginResult> LoginAsync(DisplayMode displayMode = DisplayMode.Visible, int timeout = 300, object extraParameters = null);

        /// <summary>
        /// Starts a login.
        /// </summary>
        /// <param name="request">The login request.</param>
        /// <returns></returns>
        Task<LoginResult> LoginAsync(LoginRequest request);

        /// <summary>
        /// Creates a logout URL.
        /// </summary>
        /// <param name="request">The logout request.</param>
        /// <returns></returns>
        Task<string> PrepareLogoutAsync(LogoutRequest request = null);

        /// <summary>
        /// Starts a logout.
        /// </summary>
        /// <param name="request">The logout request.</param>
        /// <returns></returns>
        Task LogoutAsync(LogoutRequest request = null);

        /// <summary>
        /// Prepares the login request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>State for initiating the authorize request and processing the response</returns>
        Task<AuthorizeState> PrepareLoginAsync(object extraParameters = null);

        /// <summary>
        /// Processes the authorize response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns>
        /// Result of the login response validation
        /// </returns>
        Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state, object extraParameters = null);

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        Task<UserInfoResult> GetUserInfoAsync(string accessToken);

        /// <summary>
        /// Refreshes an access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="extraParameters">The extra parameters.</param>
        /// <returns>
        /// A token response.
        /// </returns>
        Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken, object extraParameters = null);


    }
}