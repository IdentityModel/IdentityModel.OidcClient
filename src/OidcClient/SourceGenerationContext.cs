using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IdentityModel.OidcClient
{
    [JsonSourceGenerationOptions(
        WriteIndented = false,
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        GenerationMode = JsonSourceGenerationMode.Metadata,
	    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(AuthorizeState))]
    [JsonSerializable(typeof(Dictionary<string, JsonElement>))]
    [JsonSerializable(typeof(OidcClientOptions))]
    internal partial class SourceGenerationContext : JsonSerializerContext
    {
    }
}