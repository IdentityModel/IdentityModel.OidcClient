// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityModel.OidcClient.Tests.Infrastructure
{
    public static class Crypto
    {
        static Crypto()
        {
            IdentityModelEventSource.ShowPII = true;
        }

        public static string UntrustedIdentityToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk4RDNBQ0YwNTcyOTlDMzc0NTA0NEJFOTE4OTg2QUQ3RUQwQUQ0QTIiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJtTk9zOEZjcG5EZEZCRXZwR0pocTEtMEsxS0kifQ.eyJuYmYiOjE0ODQyOTc1MjksImV4cCI6MTQ4NDI5NzgyOSwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjoibmF0aXZlLmh5YnJpZCIsIm5vbmNlIjoiMjcwODQ5YjYwZjllZTJhOTA4NjAwZTdkZmIyMzE5NTUiLCJpYXQiOjE0ODQyOTc1MjksImF0X2hhc2giOiJRMmV5b3BkbktIc1QxY0VTbHdscTNRIiwic2lkIjoiOWZkYzRiMmJkNGMwY2M5MDE2NmRkMzZmYmZhMGY0MWYiLCJzdWIiOiI4ODQyMTExMyIsImF1dGhfdGltZSI6MTQ4NDI5NzUyOCwiaWRwIjoibG9jYWwiLCJhbXIiOlsicHdkIl19.jlGE9Lh5ZpU2Kne5-l9bMpJpUMUBUBDukKcIfK62h24ArI4QxVlG5mQPG0_vRRZYMtZDtkk78NDTttH5k0o21igvWAtoApxHGZv4NvnriVEWOFTidlPSRrcB77o__Gv0fnngSIJ03bENxRkZHEcTBP312kJk2khy-8kSvykYNhh0HFvkCKa8oGHu0Q_DJQH1xZIKqoTbPCzGQSLuqObNmg6Xkvg4h38MHOh1LIEt1PPhYkCJSBA6fceqtmv95hXwPTi4DY4-OwRpvm-_FHQvnjEfRPyltus_fJKijWIVSNWKqvZxxGG2hvBFsBgnvLu6L5mqfqQiOJYQDWhtenuMjg";

        public static RsaSecurityKey CreateKey()
        {
            var rsa = RSA.Create();

#if NET472
            if (rsa.KeySize < 2048)
            {
                rsa.Dispose();
                rsa = new RSACryptoServiceProvider(2048);
            }
#endif
            RsaSecurityKey key = null;
#if NET472
            if (rsa is RSACryptoServiceProvider) 
            {
                var parameters = rsa.ExportParameters(includePrivateParameters: true);
                key = new RsaSecurityKey(parameters);
                        
                rsa.Dispose();
            }   
#endif
            if (key == null)
            {
                key = new RsaSecurityKey(rsa);
            }

            key.KeyId = "1";
            return key;
        }

        public static IdentityModel.Jwk.JsonWebKeySet CreateKeySet(RsaSecurityKey key)
        {
            var parameters = key.Rsa?.ExportParameters(false) ?? key.Parameters;
            var exponent = Base64Url.Encode(parameters.Exponent);
            var modulus = Base64Url.Encode(parameters.Modulus);

            var webKey = new IdentityModel.Jwk.JsonWebKey
            { 
                Kty = "RSA",
                Use = "sig",
                Kid = key.KeyId,
                E = exponent,
                N = modulus,
            };

            var set = new IdentityModel.Jwk.JsonWebKeySet();
            set.Keys.Add(webKey);
            return set;
        }

        public static string CreateJwt(RsaSecurityKey key, string issuer, string audience, params Claim[] claims)
        {
            var jwtClaims = new List<Claim>(claims);
            jwtClaims.Add(new Claim(JwtClaimTypes.IssuedAt, "now"));

            var jwt = new JwtSecurityToken(
                issuer,
                audience,
                jwtClaims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddHours(1),
                new SigningCredentials(key, "RS256"));

            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();

            return handler.WriteToken(jwt);
        }

        public static string HashData(string data)
        {
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(data));

                var leftPart = new byte[16];
                Array.Copy(hash, leftPart, 16);

                return Base64Url.Encode(leftPart);
            }
        }
    }
}