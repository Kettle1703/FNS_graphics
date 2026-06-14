using System;
using System.IO;

namespace FNS_graphics
{
    internal static class App_storage_paths
    {
        internal static readonly string Executable_directory_path = Build_executable_directory_path();

        internal static readonly string Crypto_directory_path = Path.Combine(
            Executable_directory_path,
            "crypto");

        internal static readonly string Json_packets_directory_path = Path.Combine(
            Executable_directory_path,
            "json_packets");

        internal static readonly string Analysis_reports_directory_path = Path.Combine(
            Executable_directory_path,
            "analysis_reports");

        internal static readonly string Analysis_report_file_path = Path.Combine(
            Analysis_reports_directory_path,
            "FNS_analysis.xlsx");

        static string Build_executable_directory_path()
        {
            string base_directory = AppContext.BaseDirectory;
            if (string.IsNullOrWhiteSpace(base_directory))
                base_directory = Environment.CurrentDirectory;

            return Path.GetFullPath(base_directory);
        }

        internal static string Resolve_from_executable_directory(string path)
        {
            string expanded_path = Environment.ExpandEnvironmentVariables((path ?? string.Empty).Trim());
            if (string.IsNullOrWhiteSpace(expanded_path))
                return Json_packets_directory_path;

            if (Path.IsPathRooted(expanded_path))
                return Path.GetFullPath(expanded_path);

            return Path.GetFullPath(Path.Combine(Executable_directory_path, expanded_path));
        }

        internal static void Ensure_crypto_directory_exists()
        {
            if (!Directory.Exists(Crypto_directory_path))
                Directory.CreateDirectory(Crypto_directory_path);
        }
    }
}
