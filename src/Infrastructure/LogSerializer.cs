// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

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

        static readonly JsonSerializerSettings jsonSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DateFormatHandling = DateFormatHandling.IsoDateFormat,
            Formatting = Formatting.Indented
        };

        static LogSerializer()
        {
            jsonSettings.Converters.Add(new StringEnumConverter());
        }

        /// <summary>
        /// Serializes the specified object.
        /// </summary>
        /// <param name="logObject">The object.</param>
        /// <returns></returns>
        public static string Serialize(object logObject)
        {
            return Enabled ? JsonConvert.SerializeObject(logObject, jsonSettings) : "Logging has been disabled";
        }
    }
}