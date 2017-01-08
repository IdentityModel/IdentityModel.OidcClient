using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace IdentityModel.OidcClient
{
    internal class CryptoHelper
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;

        public CryptoHelper(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<CryptoHelper>();
        }

        public HashAlgorithm GetMatchingHashAlgorithm(string signatureAlgorithm)
        {
            _logger.LogDebug("Determining matching hash algorithm for {signatureAlgorithm}", signatureAlgorithm);

            var signingAlgorithmBits = int.Parse(signatureAlgorithm.Substring(2));
            
            switch (signingAlgorithmBits)
            {
                case 256:
                    _logger.LogDebug("SHA256");
                    return SHA256.Create();
                case 384:
                    _logger.LogDebug("SHA384");
                    return SHA384.Create();
                case 512:
                    _logger.LogDebug("SHA512");
                    return SHA512.Create();
                default:
                    return null;
            }
        }

        public Pkce CreatePkceData()
        {
            var pkce = new Pkce
            {
                CodeVerifier = CryptoRandom.CreateUniqueId(16)
            };

            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(pkce.CodeVerifier));
                pkce.CodeChallenge = Base64Url.Encode(challengeBytes);
            }

            return pkce;
        }

        internal class Pkce
        {
            public string CodeVerifier { get; set; }
            public string CodeChallenge { get; set; }
        }
    }
}