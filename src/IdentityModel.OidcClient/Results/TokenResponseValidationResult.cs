namespace IdentityModel.OidcClient.Results
{
    internal class TokenResponseValidationResult : Result
    {
        public TokenResponseValidationResult(string error)
        {
            Error = error;
        }

        public TokenResponseValidationResult(IdentityTokenValidationResult result)
        {
            IdentityTokenValidationResult = result;
        }

        public IdentityTokenValidationResult IdentityTokenValidationResult { get; set; }
    }
}