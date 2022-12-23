using IdentityModel.OidcClient;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ApiClient.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class OidcController : ControllerBase
    {
        [HttpGet]
        [Route("sso")]
        public async Task<IActionResult> InitiateSingleSignOn()
        {
            var options = new OidcClientOptions
            {
                Authority = "https://demo.duendesoftware.com",
                ClientId = "interactive.public.short",
                RedirectUri = "https://localhost:7088/api/auth/callback",
                Scope = "openid profile api offline_access",
                FilterClaims = false,

                IdentityTokenValidator = new JwtHandlerIdentityTokenValidator(),
                RefreshTokenInnerHttpHandler = new SocketsHttpHandler()
            };
            OidcClient oidcClient = new OidcClient(options);
            var redirectionUrl = await oidcClient.InitiateLogin();

            return Redirect(redirectionUrl);
        }

        [HttpGet]
        [Route("callback")]
        public async Task<IActionResult> AuthenticationCallback([FromQuery] string code, [FromQuery] string scope, 
            [FromQuery] string state, [FromQuery(Name = "session_state")] string sessionState, [FromQuery] string iss)
        {
            var options = new OidcClientOptions
            {
                Authority = "https://demo.duendesoftware.com",
                ClientId = "interactive.public.short",
                RedirectUri = "https://localhost:7088/api/auth/callback",
                Scope = "openid profile api offline_access",
                FilterClaims = false,

                IdentityTokenValidator = new JwtHandlerIdentityTokenValidator(),
                RefreshTokenInnerHttpHandler = new SocketsHttpHandler()
            };
            OidcClient oidcClient = new OidcClient(options);
            await oidcClient.CompleteLogin(code, scope, state, sessionState, iss);
            return new OkObjectResult(code);
        }
    }
}
