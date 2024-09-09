// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Results;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// Models pluggable identity token validation
    /// </summary>
    public interface IIdentityTokenValidator
    {
        /// <summary>
        /// Validates an identity token
        /// </summary>
        /// <param name="identityToken"></param>
        /// <param name="options"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default);
    }
}