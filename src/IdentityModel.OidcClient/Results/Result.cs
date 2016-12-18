namespace IdentityModel.OidcClient
{
    public class Result
    {
        public Result()
        {

        }

        public Result(string error)
        {
            Error = error;
        }

        public bool Success => string.IsNullOrWhiteSpace(Error);
        public string Error { get; set; }
    }
}