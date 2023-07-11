using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IdentityModel.OidcClient
{
#if NET5_0_OR_GREATER
    [JsonSourceGenerationOptions(
        WriteIndented = false,
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        GenerationMode = JsonSourceGenerationMode.Metadata)]
    [JsonSerializable(typeof(AuthorizeState))]
    [JsonSerializable(typeof(Dictionary<string, JsonElement>))]
    [JsonSerializable(typeof(OidcClientOptions))]
    internal partial class SourceGenerationContext : JsonSerializerContext
    {
    }
#endif
}