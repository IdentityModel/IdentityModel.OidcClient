// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;

namespace ApiHost;

public interface IReplayCache
{
    /// <summary>
    /// Adds a handle to the cache 
    /// </summary>
    /// <param name="purpose"></param>
    /// <param name="handle"></param>
    /// <param name="expiration"></param>
    /// <returns></returns>
    Task AddAsync(string purpose, string handle, DateTimeOffset expiration);


    /// <summary>
    /// Checks if a cached handle exists 
    /// </summary>
    /// <param name="purpose"></param>
    /// <param name="handle"></param>
    /// <returns></returns>
    Task<bool> ExistsAsync(string purpose, string handle);
}
