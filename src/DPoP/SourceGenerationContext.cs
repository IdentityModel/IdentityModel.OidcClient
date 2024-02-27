using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient.DPoP
{
    [JsonSourceGenerationOptions(
        WriteIndented = false,
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        GenerationMode = JsonSourceGenerationMode.Metadata,
	    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(JsonWebKey))]
    [JsonSerializable(typeof(DPoPProofPayload))]
    internal partial class SourceGenerationContext : JsonSerializerContext
    {
    }
}