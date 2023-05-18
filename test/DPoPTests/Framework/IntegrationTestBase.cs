// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;

namespace DPoPTests;

public class IntegrationTestBase
{
    protected readonly IdentityServerHost IdentityServerHost;
    protected ApiHost ApiHost;

    public IntegrationTestBase()
    {
        IdentityServerHost = new IdentityServerHost();
        IdentityServerHost.InitializeAsync().Wait();

        ApiHost = new ApiHost(IdentityServerHost);
        ApiHost.InitializeAsync().Wait();
    }
}