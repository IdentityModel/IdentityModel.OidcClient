// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;
#if NET5_0_OR_GREATER
using System.Text.Json.Serialization.Metadata;
#endif

namespace IdentityModel.OidcClient.Infrastructure
{
    /// <summary>
    /// Helper to JSON serialize object data for logging.
    /// </summary>
    public static class LogSerializer
    {
        /// <summary>
        /// Allows log serialization to be disabled, for example, for platforms
        /// that don't support serialization of arbitarary objects to JSON.
        /// </summary>
        public static bool Enabled = true;

        static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions()
        {
            IgnoreNullValues = true,
            WriteIndented = true
        };

        static LogSerializer()
        {
            JsonOptions.Converters.Add(new JsonStringEnumConverter());
        }

        /// <summary>
        /// Serializes the specified object.
        /// </summary>
        /// <param name="logObject">The object.</param>
        /// <returns></returns>
        public static string Serialize<T>(T logObject)
        {
#if NET5_0_OR_GREATER
            return Enabled ? JsonSerializer.Serialize(logObject, (JsonTypeInfo<T>)SourceGenerationContext.Default.GetTypeInfo(typeof(T))) : "Logging has been disabled";
#else
            return Enabled ? JsonSerializer.Serialize(logObject, JsonOptions) : "Logging has been disabled";
#endif
		}
    }
}