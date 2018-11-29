using System.Net.Http;

namespace IdentityModel.OidcClient.Infrastructure
{
    internal static class OidcClientOptionsExtensions
    {
        public static HttpClient CreateClient(this OidcClientOptions options)
        {
            HttpClient client;

            if (options.BackchannelHandler != null)
            {
                client = new HttpClient(options.BackchannelHandler);
            }
            else
            {
                client = new HttpClient();
            }

            client.Timeout = options.BackchannelTimeout;
            return client;
        }
    }
}