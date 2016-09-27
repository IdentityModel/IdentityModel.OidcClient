//// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
//// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


//using Newtonsoft.Json.Linq;
//using System;
//using System.Collections.Generic;
//using System.Net.Http;
//using System.Threading.Tasks;

//namespace IdentityModel.OidcClient
//{
//    public class EndpointIdentityTokenValidator : IIdentityTokenValidator
//    {
//        private readonly string _endpoint;

//        public EndpointIdentityTokenValidator(string authority)
//        {
//            _endpoint = authority.EnsureTrailingSlash() + "connect/identitytokenvalidation";
//        }

//        public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
//        {
//            var client = new HttpClient();

//            var form = new Dictionary<string, string>
//            {
//                { "token", identityToken },
//                { "client_id", clientId }
//            };

//            var response = await client.PostAsync(
//                new Uri(_endpoint),
//                new FormUrlEncodedContent(form));

//            if (!response.IsSuccessStatusCode)
//            {
//                return new IdentityTokenValidationResult
//                {
//                    Success = false,
//                    Error = response.ReasonPhrase
//                };
//            }

//            var json = JObject.Parse(await response.Content.ReadAsStringAsync());

//            return new IdentityTokenValidationResult
//            {
//                Success = true,
//                Claims = json.ToClaims(),
//                SignatureAlgorithm = "RS256"
//            };
//        }
//    }
//}