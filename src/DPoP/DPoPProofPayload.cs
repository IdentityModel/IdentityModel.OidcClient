// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Json.Serialization;

namespace IdentityModel.OidcClient.DPoP;

/// <summary>
///  Internal class to aid serialization of DPoP proof token payloads. Giving
///  each claim a property allows us to add this type to the source generated
///  serialization
/// </summary>
internal class DPoPProofPayload
{
    [JsonPropertyName(JwtClaimTypes.JwtId)]
    internal string JwtId { get; set; } = default!;
    [JsonPropertyName(JwtClaimTypes.DPoPHttpMethod)]
    internal string DPoPHttpMethod { get; set; } = default!;
    [JsonPropertyName(JwtClaimTypes.DPoPHttpUrl)]
    internal string DPoPHttpUrl { get; set; } = default!;
    [JsonPropertyName(JwtClaimTypes.IssuedAt)]
    internal long IssuedAt { get; set; }
    [JsonPropertyName(JwtClaimTypes. DPoPAccessTokenHash)]
    internal string? DPoPAccessTokenHash { get; set; }
    [JsonPropertyName(JwtClaimTypes. Nonce)]
    internal string? Nonce { get; set; }
}