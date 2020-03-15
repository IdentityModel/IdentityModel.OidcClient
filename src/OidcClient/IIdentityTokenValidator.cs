using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Results;

namespace IdentityModel.OidcClient
{
    public interface IIdentityTokenValidator
    {
        Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default);
    }
}