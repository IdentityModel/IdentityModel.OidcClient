//// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
//// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


//using Newtonsoft.Json;
//using System;
//using System.Collections.Generic;
//using System.Net.Http;
//using System.Threading.Tasks;
//using System.Text;
//using Newtonsoft.Json.Linq;
//using System.Linq;
//using IdentityModel.Jwk;

//namespace IdentityModel.OidcClient
//{
//    /// <summary>
//    /// Information about an OpenID Connect provider
//    /// </summary>
//    public class ProviderInformation
//    {
//        //private static ILog Logger = LogProvider.For<ProviderInformation>();

//        /// <summary>
//        /// Gets or sets the name of the issuer.
//        /// </summary>
//        /// <value>
//        /// The name of the issuer.
//        /// </value>
//        public string IssuerName { get; set; }

//        /// <summary>
//        /// Gets or sets the key set.
//        /// </summary>
//        /// <value>
//        /// The key set.
//        /// </value>
//        public JsonWebKeySet KeySet { get; set; }

//        /// <summary>
//        /// Gets or sets the token endpoint.
//        /// </summary>
//        /// <value>
//        /// The token endpoint.
//        /// </value>
//        public string TokenEndpoint { get; set; }

//        /// <summary>
//        /// Gets or sets the authorize endpoint.
//        /// </summary>
//        /// <value>
//        /// The authorize endpoint.
//        /// </value>
//        public string AuthorizeEndpoint { get; set; }

//        /// <summary>
//        /// Gets or sets the end session endpoint.
//        /// </summary>
//        /// <value>
//        /// The end session endpoint.
//        /// </value>
//        public string EndSessionEndpoint { get; set; }

//        /// <summary>
//        /// Gets or sets the user information endpoint.
//        /// </summary>
//        /// <value>
//        /// The user information endpoint.
//        /// </value>
//        public string UserInfoEndpoint { get; set; }

//        /// <summary>
//        /// Gets or sets the token end point authentication methods.
//        /// </summary>
//        /// <value>
//        /// The token end point authentication methods.
//        /// </value>
//        public IEnumerable<string> TokenEndPointAuthenticationMethods { get; set; } = new string[] { };

//        /// <summary>
//        /// Validates this instance.
//        /// </summary>
//        /// <exception cref="System.InvalidOperationException">
//        /// Missing token endpoint.
//        /// or
//        /// Missing authorize endpoint.
//        /// </exception>
//        public void Validate()
//        {
//            if (string.IsNullOrEmpty(TokenEndpoint)) throw new InvalidOperationException("Missing token endpoint.");
//            if (string.IsNullOrEmpty(AuthorizeEndpoint)) throw new InvalidOperationException("Missing authorize endpoint.");
//        }

//        /// <summary>
//        /// Loads from metadata.
//        /// </summary>
//        /// <param name="authority">The authority.</param>
//        /// <param name="validateIssuerName">if set to <c>true</c> the issuer name gets validated against the authority.</param>
//        /// <returns>Provider information</returns>
//        /// <exception cref="System.InvalidOperationException">
//        /// </exception>
//        public static async Task<ProviderInformation> LoadFromMetadataAsync(string authority, bool validateIssuerName = true, HttpMessageHandler innerHandler = null, int timeout = 30)
//        {
//            var handler = innerHandler ?? new HttpClientHandler();
//            var client = new HttpClient(handler);
//            client.Timeout = TimeSpan.FromSeconds(timeout);

//            var url = authority.EnsureTrailingSlash() + ".well-known/openid-configuration";

//            //Logger.Debug($"fetching discovery document from: {url}");

//            var response = await client.GetAsync(url).ConfigureAwait(false);
//            if (!response.IsSuccessStatusCode)
//            {
//                var error = $"an error occurred while retrieving the discovery document ({url}): " +
//                    await FormatErrorAsync(response).ConfigureAwait(false);

//                //Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
//            var doc = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
//            var info = new ProviderInformation();

//            // issuer is required
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

//            // validate issuer name against authority, if requested
//            if (validateIssuerName)
//            {
//                if (!string.Equals(authority.RemoveTrailingSlash(), info.IssuerName.RemoveTrailingSlash(), StringComparison.OrdinalIgnoreCase))
//                {
//                    var error = $"issuer name of '{info.IssuerName}' does not match authority '{authority}'";
                
//                    Logger.Error(error);
//                    throw new InvalidOperationException(error);
//                }
//            }

//            // authorize endpoint is required
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

//            // token endpoint is required
//            if (doc.ContainsKey("token_endpoint"))
//            {
//                info.TokenEndpoint = doc["token_endpoint"].ToString();
//                //Logger.Debug($"token endpoint: {info.TokenEndpoint}");
//            }
//            else
//            {
//                var error = "token endpoint is missing in discovery doc.";

//                //Logger.Error(error);
//                throw new InvalidOperationException(error);
//            }

//            // end_session endpoint is optional
//            if (doc.ContainsKey("end_session_endpoint"))
//            {
//                info.EndSessionEndpoint = doc["end_session_endpoint"].ToString();
//                Logger.Debug($"end_session endpoint: {info.EndSessionEndpoint}");
//            }
//            else
//            {
//                Logger.Debug("no end_session endpoint");
//            }

//            // userinfo endpoint is optional, but required for the load profile feature
//            if (doc.ContainsKey("userinfo_endpoint"))
//            {
//                info.UserInfoEndpoint = doc["userinfo_endpoint"].ToString();
//                Logger.Debug($"userinfo_endpoint: {info.UserInfoEndpoint}");
//            }
//            else
//            {
//                Logger.Debug("no userinfo_endpoint");
//            }

//            if (doc.ContainsKey("token_endpoint_auth_methods_supported"))
//            {
//                info.TokenEndPointAuthenticationMethods = 
//                    ((JArray)doc["token_endpoint_auth_methods_supported"]).Select(x => (string)x).ToArray();
//            }

//            // parse web key set
//            if (doc.ContainsKey("jwks_uri"))
//            {
//                var jwksUri = doc["jwks_uri"].ToString();

//                var jwksResponse = await client.GetAsync(jwksUri).ConfigureAwait(false);
//                if (!jwksResponse.IsSuccessStatusCode)
//                {
//                    var error = $"an error occurred while retrieving the JWKS document ({jwksUri}) : " +
//                        await FormatErrorAsync(jwksResponse).ConfigureAwait(false);

//                    Logger.Error(error);
//                    throw new InvalidOperationException(error);
//                }

//                var jwks = await jwksResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

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

//        private static async Task<string> FormatErrorAsync(HttpResponseMessage response)
//        {
//            var output = new StringBuilder();

//            output.Append("Status: " + response.StatusCode + ";");
//            output.Append("Headers: " + response.Headers.ToString() + ";");
//            output.Append("Body: " + await response.Content.ReadAsStringAsync().ConfigureAwait(false) + ";");

//            return output.ToString();
//        }
//    }
//}