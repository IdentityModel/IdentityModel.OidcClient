// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient.DPoP;

/// <summary>
/// Helper to create JSON web keys.
/// </summary>
public static class JsonWebKeys
{
    /// <summary>
    /// Creates a new RSA JWK.
    /// </summary>
    public static JsonWebKey CreateRsa(string algorithm = OidcConstants.Algorithms.Asymmetric.PS256)
    {
        var rsaKey = new RsaSecurityKey(RSA.Create());
    
        var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(rsaKey);
        jwk.Alg = algorithm;
    
        return jwk;
    }
    
    /// <summary>
    /// Creates a new RSA JWK string.
    /// </summary>
    public static string CreateRsaJson(string algorithm = OidcConstants.Algorithms.Asymmetric.PS256)
    {
        return JsonSerializer.Serialize(CreateRsa(algorithm), SourceGenerationContext.Default.JsonWebKey);
    }
    
    /// <summary>
    /// Creates a new ECDSA JWK.
    /// </summary>
    public static JsonWebKey CreateECDsa(string algorithm = OidcConstants.Algorithms.Asymmetric.ES256)
    {
        var ecKey = new ECDsaSecurityKey(
            ECDsa.Create(GetCurveFromCrvValue(GetCurveNameFromSigningAlgorithm(algorithm))));

        var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(ecKey);
        jwk.Alg = algorithm;
    
        return jwk;
    }
    
    /// <summary>
    /// Creates a new ECDSA JWK string.
    /// </summary>
    public static string CreateECDsaJson(string algorithm = OidcConstants.Algorithms.Asymmetric.ES256)
    {
        return JsonSerializer.Serialize(CreateECDsa(algorithm), SourceGenerationContext.Default.JsonWebKey);
    }
    
    internal static string GetCurveNameFromSigningAlgorithm(string alg)
    {
        return alg switch
        {
            "ES256" => "P-256",
            "ES384" => "P-384",
            "ES512" => "P-521",
            _ => throw new InvalidOperationException($"Unsupported alg type of {alg}"),
        };
    }
    
    /// <summary>
    /// Returns the matching named curve for RFC 7518 crv value
    /// </summary>
    internal static ECCurve GetCurveFromCrvValue(string crv)
    {
        return crv switch
        {
            JsonWebKeyECTypes.P256 => ECCurve.NamedCurves.nistP256,
            JsonWebKeyECTypes.P384 => ECCurve.NamedCurves.nistP384,
            JsonWebKeyECTypes.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidOperationException($"Unsupported curve type of {crv}"),
        };
    }
}