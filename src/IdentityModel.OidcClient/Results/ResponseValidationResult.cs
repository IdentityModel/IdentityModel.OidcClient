using IdentityModel.Client;
using System.Security.Claims;

namespace IdentityModel.OidcClient
{
    public class ResponseValidationResult : Result
    {
        public AuthorizeResponse AuthorizeResponse { get; set; }
        public TokenResponse TokenResponse { get; set; }
        public ClaimsPrincipal User { get; set; }
    }
}