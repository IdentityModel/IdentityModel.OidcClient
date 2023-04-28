using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.DPoP
{
    public class ProofTokenValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; }
        public IDictionary<string, object> Payload { get; set; }
        public JsonWebKey JsonWebKey { get; set; }
    }
}