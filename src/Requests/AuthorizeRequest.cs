using IdentityModel.OidcClient.Browser;
using System.Collections.Generic;

namespace IdentityModel.OidcClient
{
    class AuthorizeRequest
    {
        public DisplayMode DisplayMode { get; set; } = DisplayMode.Visible;
        public int Timeout { get; set; } = 300;
        public IDictionary<string, string> ExtraParameters = new Dictionary<string, string>();
    }
}