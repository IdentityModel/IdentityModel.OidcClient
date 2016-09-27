// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public interface IIdentityTokenValidator
    {
        Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, DiscoveryResponse providerInformation);
    }
}