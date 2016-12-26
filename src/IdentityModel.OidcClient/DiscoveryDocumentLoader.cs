using IdentityModel.Client;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    public class DiscoveryDocumentLoader
    {
        private ILogger _logger;
        private readonly OidcClientOptions _options;

        public DiscoveryDocumentLoader(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<DiscoveryDocumentLoader>();
        }

        public async Task<DiscoveryResult> LoadAsync()
        {
            var client = new DiscoveryClient(_options.Authority, _options.BackchannelHandler);
            client.Timeout = _options.BackchannelTimeout;

            var disco = await client.GetAsync();
            if (disco.IsError)
            {
                return new DiscoveryResult { Error = disco.Error };
            }

            var info = Convert(disco);
            var error = Validate(info, _options.Policy);

            if (error.IsMissing())
            {
                return new DiscoveryResult { ProviderInformation = info };
            }
            else
            {
                return new DiscoveryResult { Error = error };
            }
        }

        public string Validate(ProviderInformation info, Policy policy)
        {
            if (info.IssuerName.IsMissing()) return "issuer name is missing";
            if (info.AuthorizeEndpoint.IsMissing()) return "authorize endpoint is missing";
            if (info.TokenEndpoint.IsMissing()) return "token endpoint is missing";

            // validate issuer name matches authority
            if (policy.ValidateIssuerName)
            {
                // todo
            }

            // make sure all endpoints are using HTTPS
            if (policy.RequireHttps)
            {
                // todo
            }

            // make sure all endpoints are under the authority
            if (policy.ValidateEndpoints)
            {
                // todo
            }

            return null;
        }

        private ProviderInformation Convert(DiscoveryResponse disco)
        {
            var info = new ProviderInformation
            {
                IssuerName = disco.Issuer,
                AuthorizeEndpoint = disco.AuthorizeEndpoint,
                TokenEndpoint = disco.TokenEndpoint,
                KeySet = disco.KeySet,

                EndSessionEndpoint = disco.EndSessionEndpoint,
                UserInfoEndpoint = disco.UserInfoEndpoint,
                TokenEndPointAuthenticationMethods = disco.TokenEndpointAuthenticationMethodsSupported
            };

            return info;
        }
    }
}