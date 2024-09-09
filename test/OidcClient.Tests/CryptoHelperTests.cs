// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text;
using FluentAssertions;
using IdentityModel;
using IdentityModel.OidcClient;
using Xunit;

public class CryptoHelperTests
{
    [Theory]
    [InlineData("asdf", "RS256")]
    [InlineData("asdf", "RS384")]
    [InlineData("asdf", "RS512")]
    public void ComputeHash_should_compute_correct_hashes_for_all_signature_algorithms(string data, string algorithmName)
    {
        var sut = new CryptoHelper(new OidcClientOptions());
        var algorithm = sut.GetMatchingHashAlgorithm(algorithmName);

        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(data));

        var bytesInLeftHalf = algorithm.HashSize / 16; // Divide by 8 for bytes and then 2 to get just half, as per spec for at_hash.

        var leftHalf = new byte[bytesInLeftHalf];
        Array.Copy(hash, leftHalf, bytesInLeftHalf);

        var hashString = Base64Url.Encode(leftHalf);

        sut.ValidateHash(data, hashString, algorithmName).Should().BeTrue();
    }

}