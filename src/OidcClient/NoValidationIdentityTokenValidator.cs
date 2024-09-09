// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Results;

namespace IdentityModel.OidcClient
{
    /// <inheritdoc />
    public class NoValidationIdentityTokenValidator : IIdentityTokenValidator
    {
        /// <inheritdoc />
        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default)
        {
            var parts = identityToken.Split('.');
            if (parts.Length != 3)
            {
                var error = new IdentityTokenValidationResult
                {
                    Error = "invalid_jwt"
                };

                return Task.FromResult(error);
            }

            var payload = Encoding.UTF8.GetString((Base64Url.Decode(parts[1])));
            var values = JsonSerializer.Deserialize(
                payload, SourceGenerationContext.Default.DictionaryStringJsonElement);

            var claims = new List<Claim>();
            foreach (var element in values)
            {
                if (element.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in element.Value.EnumerateArray())
                    {
                        claims.Add(new Claim(element.Key, item.ToString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(element.Key, element.Value.ToString()));
                }
            }

            var result = new IdentityTokenValidationResult
            {
                SignatureAlgorithm = "none",
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "none", "name", "role"))
            };

            return Task.FromResult(result);
        }
    }
}