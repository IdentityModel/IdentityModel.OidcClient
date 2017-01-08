using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace IdentityModel.OidcClient.Infrastructure
{
    /// <summary>
    /// Helper to JSON serialize object data for logging.
    /// </summary>
    internal static class LogSerializer
    {
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
            return JsonConvert.SerializeObject(logObject, jsonSettings);
        }
    }
}