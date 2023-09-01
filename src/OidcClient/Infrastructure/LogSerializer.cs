// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

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
#pragma warning disable SYSLIB0020 // Type or member is obsolete
			IgnoreNullValues = true,
#pragma warning restore SYSLIB0020 // Type or member is obsolete
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
            return Enabled ?
                JsonSerializer.Serialize(logObject, (JsonTypeInfo<T>)SourceGenerationContext.Default.GetTypeInfo(typeof(T))) :
                "Logging has been disabled";
		}
    }
}