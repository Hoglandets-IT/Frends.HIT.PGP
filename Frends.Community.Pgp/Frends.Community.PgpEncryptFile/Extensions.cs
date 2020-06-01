using System;

namespace Frends.Community.PgpEncrypt
{
    static class Extensions
    {
        /// <summary>
        /// Convert enum to given type
        /// </summary>
        /// <typeparam name="TEnum">Enum to convert to</typeparam>
        /// <param name="source">Enum to convert from</param>
        public static TEnum ConvertEnum<TEnum>(this Enum source)
        {
            return (TEnum)Enum.Parse(typeof(TEnum), source.ToString(), true);
        }
    }
}
