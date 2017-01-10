namespace IdentityModel.OidcClient
{
    public class Result
    {
        public bool IsError => Error.IsPresent();
        public string Error { get; set; }
    }
}