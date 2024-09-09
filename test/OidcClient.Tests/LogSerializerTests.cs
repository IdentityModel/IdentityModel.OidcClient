// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FluentAssertions;
using System;
using Xunit;
using IdentityModel.OidcClient.Infrastructure;

namespace IdentityModel.OidcClient.Tests
{
    public class LogSerializerTests
    {
        [Fact]
        // This test exists to make sure that the public api for the log
        // serializer can serialize types that aren't part of the source
        // generation context. There is an internal api that does use the source
        // generation context types. We should always use that other serialize
        // method internally in order to be trimmable. The overload in this test
        // exists to avoid a breaking change. 
        public void LogSerializer_should_serialize_arbitrary_types()
        {
            // We instantiate the test class as an example of a class that is
            // not (and won't ever be) in the generation context.
            var act = () => LogSerializer.Serialize(new LogSerializerTests());
            act.Should().NotThrow<Exception>();
        }
    }
}