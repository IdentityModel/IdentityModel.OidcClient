// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient.WebView
{
    public interface IWebView
    {
        Task<InvokeResult> InvokeAsync(InvokeOptions options);

        event EventHandler<HiddenModeFailedEventArgs> HiddenModeFailed;
    }
}