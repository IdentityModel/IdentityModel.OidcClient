//// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
//// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


//using IdentityModel.Jwt;
//using IdentityModel.OidcClient.Logging;
//using Newtonsoft.Json;
//using System;
//using System.Collections.Generic;
//using System.Net.Http;
//using System.Threading.Tasks;

//namespace IdentityModel.OidcClient
//{
//    public class ProviderInformation
//    {
//        private static ILog Logger = LogProvider.For<ProviderInformation>();

//        public string IssuerName { get; set; }
//        public JsonWebKeySet KeySet { get; set; }

//        public string TokenEndpoint { get; set; }
//        public string AuthorizeEndpoint { get; set; }
//        public string EndSessionEndpoint { get; set; }
//        public string UserInfoEndpoint { get; set; }

//        public void Validate()
//        {
//            if (string.IsNullOrEmpty(TokenEndpoint)) throw new InvalidOperationException("Missing token endpoint.");
//            if (string.IsNullOrEmpty(AuthorizeEndpoint)) throw new InvalidOperationException("Missing authorize endpoint.");
//        }

//        public static async Task<ProviderInformation> LoadFromMetadataAsync(string authority)
//        {
//            var client = new HttpClient();
//            var url = authority.EnsureTrailingSlash() + ".well-known/openid-configuration";

//            Logger.Debug($"fetching discovery document from: {url}");

//            var json = await client.GetStringAsync(url).ConfigureAwait(false);
//            var doc = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
//            var info = new ProviderInformation();

//            if (doc.ContainsKey("issuer"))
//            {
//                info.IssuerName = doc["issuer"].ToString();
//                Logger.Debug($"issuer name: {info.IssuerName}");
//            }
//            else
//            {
//                var error = "issuer name is missing in discovery doc.";

//                Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            if (doc.ContainsKey("authorization_endpoint"))
//            {
//                info.AuthorizeEndpoint = doc["authorization_endpoint"].ToString();
//                Logger.Debug($"authorization endpoint: {info.AuthorizeEndpoint}");
//            }
//            else
//            {
//                var error = "authorization endpoint is missing in discovery doc.";

//                Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            if (doc.ContainsKey("token_endpoint"))
//            {
//                info.TokenEndpoint = doc["token_endpoint"].ToString();
//                Logger.Debug($"token endpoint: {info.TokenEndpoint}");
//            }
//            else
//            {
//                var error = "token endpoint is missing in discovery doc.";

//                Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            if (doc.ContainsKey("end_session_endpoint"))
//            {
//                info.EndSessionEndpoint = doc["end_session_endpoint"].ToString();
//                Logger.Debug($"end_session endpoint: {info.EndSessionEndpoint}");
//            }
//            else
//            {
//                Logger.Debug("no end_session endpoint");
//            }

//            if (doc.ContainsKey("userinfo_endpoint"))
//            {
//                info.UserInfoEndpoint = doc["userinfo_endpoint"].ToString();
//                Logger.Debug($"userinfo_endpoint: {info.UserInfoEndpoint}");
//            }
//            else
//            {
//                Logger.Debug("no userinfo_endpoint");
//            }

//            // parse web key set
//            if (doc.ContainsKey("jwks_uri"))
//            {
//                var jwksUri = doc["jwks_uri"].ToString();
//                var jwks = await client.GetStringAsync(jwksUri).ConfigureAwait(false);

//                Logger.Debug($"jwks: {jwks}");
//                info.KeySet = new JsonWebKeySet(jwks);
//            }
//            else
//            {
//                var error = "jwks_uri is missing in discovery doc.";

//                Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            return info;
//        }
//    }
//}