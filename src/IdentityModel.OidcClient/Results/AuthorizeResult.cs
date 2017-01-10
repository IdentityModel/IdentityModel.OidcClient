namespace IdentityModel.OidcClient.Results
{
    public class AuthorizeResult : Result
    {
        public string Data { get; set; }
        public AuthorizeState State { get; set; }
    }
}