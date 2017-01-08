//using Microsoft.Extensions.Logging;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Threading.Tasks;

//namespace IdentityModel.OidcClient
//{
//    public class ClaimsProcessor
//    {
//        private readonly ILogger _logger;
//        private readonly OidcClientOptions _options;

//        public ClaimsProcessor(OidcClientOptions options)
//        {
//            _options = options;
//            _logger = options.LoggerFactory.CreateLogger<ClaimsProcessor>();
//        }

//        public async Task<LoginResult> ProcessClaimsAsync(ResponseValidationResult result)
//        {
//            _logger.LogTrace("ProcessClaimsAsync");

//            // get profile if enabled
//            if (_options.LoadProfile)
//            {
//                //Logger.Debug("load profile");

//                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken);

//                if (!userInfoResult.Success)
//                {
//                    return new LoginResult(userInfoResult.Error);
//                }

//                Logger.Debug("profile claims:");
//                Logger.LogClaims(userInfoResult.Claims);

//                var primaryClaimTypes = result.Claims.Select(c => c.Type).Distinct();
//                foreach (var claim in userInfoResult.Claims.Where(c => !primaryClaimTypes.Contains(c.Type)))
//                {
//                    result.Claims.Add(claim);
//                }
//            }
//            else
//            {
//                Logger.Debug("don't load profile");
//            }

//            // success
//            var loginResult = new LoginResult
//            {
//                Claims = FilterClaims(result.Claims),
//                AccessToken = result.TokenResponse.AccessToken,
//                RefreshToken = result.TokenResponse.RefreshToken,
//                AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
//                IdentityToken = result.TokenResponse.IdentityToken,
//                AuthenticationTime = DateTime.Now
//            };

//            if (!string.IsNullOrWhiteSpace(result.TokenResponse.RefreshToken))
//            {
//                var providerInfo = await _options.GetProviderInformationAsync();

//                loginResult.Handler = new RefeshTokenHandler(
//                    await TokenClientFactory.CreateAsync(_options),
//                    result.TokenResponse.RefreshToken,
//                    result.TokenResponse.AccessToken);
//            }

//            return loginResult;
//        }

//        private Claims FilterClaims(Claims claims)
//        {
//            Logger.Debug("filtering claims");

//            if (_options.FilterClaims)
//            {
//                claims = claims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToClaims();
//            }

//            Logger.Debug("filtered claims:");
//            Logger.LogClaims(claims);

//            return claims;
//        }

//    }
//}
