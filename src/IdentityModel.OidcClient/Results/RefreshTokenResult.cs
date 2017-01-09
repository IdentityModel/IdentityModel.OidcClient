namespace IdentityModel.OidcClient.Results
{
    public class RefreshTokenResult : Result
    {
        public string IdentityToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
    }
}