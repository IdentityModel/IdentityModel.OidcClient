// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    public class Policy
    {
        public DiscoveryPolicy Discovery { get; set; } = new DiscoveryPolicy();

        public bool RequireCodeHash { get; set; } = true;
        public bool RequireAccessTokenHash { get; set; } = true;
        public bool RequireIdentityTokenOnRefreshTokenResponse { get; set; } = false;

        public ICollection<string> SupportedAlgorithms { get; set; } = new HashSet<string>
        {
            OidcConstants.Algorithms.Asymmetric.RS256,
            OidcConstants.Algorithms.Asymmetric.RS384,
            OidcConstants.Algorithms.Asymmetric.RS512
        };
    }
}