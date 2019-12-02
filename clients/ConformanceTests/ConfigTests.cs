using FluentAssertions;
using IdentityModel.OidcClient;
using System.Threading.Tasks;

namespace ConformanceTests
{
    // test description: https://rp.certification.openid.net:8080/list?profile=CNF
    public class ConfigTests
    {
        string _rpId = "identitymodel.oidcclient.config";
        
        public async Task Start()
        {
            //await rp_discovery_jwks_uri_keys();
            //await rp_discovery_issuer_not_matching_config();
            //await rp_discovery_openid_configuration();
            //await rp_id_token_sig_none();
            //await rp_key_rotation_op_sign_key_native();
        }

        // The Relying Party uses keys from the jwks_uri which has been obtained from the OpenID Provider Metadata.
        // Should be able to verify signed responses and/or encrypt requests using obtained keys.
        public async Task rp_discovery_jwks_uri_keys()
        {
            var helper = new Helper(_rpId, "rp-discovery-jwks_uri-keys");
            var options = await helper.RegisterForCode();

            options.Scope = "openid";
            
            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());

            result.IsError.Should().BeFalse();
            helper.ShowResult(result);
        }

        // Retrieve OpenID Provider Configuration Information for OpenID Provider from the .well-known/openid-configuration path. 
        // Verify that the issuer in the provider configuration matches the one returned by WebFinger.
        // Identify that the issuers are not matching and reject the provider configuration.
        public async Task rp_discovery_issuer_not_matching_config()
        {
            var helper = new Helper(_rpId, "rp-discovery-issuer-not-matching-config");
            var options = await helper.RegisterForCode();

            options.Scope = "openid";

            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());

            result.IsError.Should().BeFalse();
            helper.ShowResult(result);
        }

        // Retrieve and use the OpenID Provider Configuration Information.
        // Read and use the JSON object returned from the OpenID Connect Provider.
        public async Task rp_discovery_openid_configuration()
        {
            var helper = new Helper(_rpId, "rp-discovery-openid-configuration");
            var options = await helper.RegisterForCode();

            options.Scope = "openid";

            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());

            result.IsError.Should().BeFalse();
            helper.ShowResult(result);
        }

        // Use Code Flow and retrieve an unsigned ID Token.
        // Accept the ID Token after doing ID Token validation.
        public async Task rp_id_token_sig_none()
        {
            var helper = new Helper(_rpId, "rp-id_token-sig-none");
            var options = await helper.RegisterForCode();

            options.Scope = "openid";

            // disable signature requirement to make this test pass
            options.Policy.RequireIdentityTokenSignature = false;

            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());

            result.IsError.Should().BeFalse();
            helper.ShowResult(result);
        }

        // Request an ID Token and verify its signature. Make a new authentication and retrieve another ID Token and verify its signature.
        // Successfully verify both ID Token signatures, fetching the rotated signing keys if the 'kid' claim in the JOSE header is unknown.
        public async Task rp_key_rotation_op_sign_key_native()
        {
            var helper = new Helper(_rpId, "rp-key-rotation-op-sign-key-native");
            var options = await helper.RegisterForCode();

            options.Scope = "openid";
            options.RefreshDiscoveryOnSignatureFailure = true;

            await helper.ResetKeyRotation();
            var client = new OidcClient(options);

            var result = await client.LoginAsync(new LoginRequest());
            result.IsError.Should().BeFalse();
            helper.ShowResult(result);
        }
    }
}