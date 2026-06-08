using System;
using System.IO;

namespace FNS_graphics
{
    internal static class App_storage_paths
    {
        internal static readonly string Crypto_directory_path = Path.Combine(
            AppContext.BaseDirectory,
            "crypto");

        internal static readonly string Json_packets_directory_path = Path.Combine(
            AppContext.BaseDirectory,
            "json_packets");

        internal static void Ensure_crypto_directory_exists()
        {
            if (!Directory.Exists(Crypto_directory_path))
                Directory.CreateDirectory(Crypto_directory_path);
        }
    }
}
