namespace IdentityModel.OidcClient
{
    public class Policy
    {
        public bool ValidateIssuerName { get; set; } = true;
        public bool ValidateEndpoints { get; set; } = true;

        public bool RequireCodeHash { get; set; } = true;
        public bool RequireAccessTokenHash { get; set; } = true;
    }
}