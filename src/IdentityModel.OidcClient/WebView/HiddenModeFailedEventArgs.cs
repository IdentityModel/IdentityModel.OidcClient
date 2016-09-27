// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.ComponentModel;

namespace IdentityModel.OidcClient.WebView
{
    public class HiddenModeFailedEventArgs : CancelEventArgs
    {
        public InvokeResult Result { get; }

        public HiddenModeFailedEventArgs(InvokeResult result)
        {
            Result = result;
        }
    }
}