using System.Collections;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    public class Policy
    {
        public bool ValidateIssuerName { get; set; } = true;
        public bool ValidateEndpoints { get; set; } = true;

        public bool RequireCodeHash { get; set; } = true;
        public bool RequireAccessTokenHash { get; set; } = true;

        public bool RequireIdentityTokenOnRefreshTokenResponse { get; set; } = true;

        public ICollection<string> SupportedAlgorithms { get; set; } = new HashSet<string>
        {
            OidcConstants.Algorithms.Asymmetric.RS256,
            OidcConstants.Algorithms.Asymmetric.RS384,
            OidcConstants.Algorithms.Asymmetric.RS512
        };
    }
}