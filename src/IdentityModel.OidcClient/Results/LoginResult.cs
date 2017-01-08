// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Net.Http;
using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    public class LoginResult : Result
    {
        public LoginResult()
        {
        }

        public LoginResult(string error)
        {
            Error = error;
        }

        public ClaimsPrincipal User { get; set; }
        public string AccessToken { get; set; }
        public string IdentityToken { get; set; }
        public string RefreshToken { get; set; }

        public DateTime AccessTokenExpiration { get; set; }
        public DateTime AuthenticationTime { get; set; }

        public HttpMessageHandler RefreshTokenHandler { get; set; }
    }
}