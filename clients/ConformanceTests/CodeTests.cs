using IdentityModel.Client;
using IdentityModel.OidcClient;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ConformanceTests
{
    public class CodeTests
    {
        string _rpId = "identitymodel.oidcclient.code";
        
        public async Task Start()
        {
            //await rp_response_type_code();
            //await rp_scope_userinfo_claims();
            //await rp_nonce_invalid();
            //await rp_token_endpoint_client_secret_basic();
            //await rp_id_token_aud();
            //await rp_id_token_kid_absent_single_jwks();
            await rp_id_token_sig_none();
        }

        // Make an authentication request using the Authorization Code Flow.
        public async Task rp_response_type_code()
        {
            var helper = new Helper(_rpId, "rp-response_type-code");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;
            
            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // 	Request claims using scope values.
        public async Task rp_scope_userinfo_claims()
        {
            var helper = new Helper(_rpId, "rp-scope-userinfo-claims");
            var options = await helper.Register();

            options.Scope = "openid profile email address phone";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // Pass a 'nonce' value in the Authentication Request.Verify the 'nonce' value returned in the ID Token.
        public async Task rp_nonce_invalid()
        {
            var helper = new Helper(_rpId, "rp-nonce-invalid");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // Use the 'client_secret_basic' method to authenticate at the Authorization Server when using the token endpoint.
        public async Task rp_token_endpoint_client_secret_basic()
        {
            var helper = new Helper(_rpId, "rp-token_endpoint-client_secret_basic");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // Request an ID token and compare its aud value to the Relying Party's 'client_id'.
        // Identify that the 'aud' value is missing or doesn't match the 'client_id' and reject the ID Token after doing ID Token validation.
        public async Task rp_id_token_aud()
        {
            var helper = new Helper(_rpId, "rp-id_token-aud");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // Request an ID token and verify its signature using the keys provided by the Issuer.
        // Use the single key published by the Issuer to verify the ID Tokens signature and accept the ID Token after doing ID Token validation.
        public async Task rp_id_token_kid_absent_single_jwks()
        {
            var helper = new Helper(_rpId, "rp-id_token-kid-absent-single-jwks");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }

        // Use Code Flow and retrieve an unsigned ID Token.
        // Accept the ID Token after doing ID Token validation.
        public async Task rp_id_token_sig_none()
        {
            var helper = new Helper(_rpId, "rp-id_token-sig-none");
            var options = await helper.Register();

            options.Scope = "openid";
            options.Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode;
            options.Policy.RequireIdentityTokenSignature = false;

            var client = new OidcClient(options);
            var result = await client.LoginAsync();

            helper.ShowResult(result);
        }
    }
}