using System;
using System.IO;
using FNS_rebuild;

namespace FNS_graphics
{
    internal sealed class Ui_toggle_settings
    {
        public bool Build_json_file { get; set; } = true;
        public bool Apply_reed_solomon_for_json { get; set; } = true;
        public string Json_transfer_directory_path { get; set; } = Build_default_json_directory_path();
        public bool Auto_sender_key_generation { get; set; } = true;
        public bool Enable_round_cipher { get; set; } = true;
        public Encryption_core_kind Encryption_core { get; set; } = Encryption_core_kind.Factorial;

        internal static string Build_default_json_directory_path()
        {
            return App_storage_paths.Json_packets_directory_path;
        }
    }

    internal static class Ui_toggle_store
    {
        static readonly object Sync_root = new();
        static Ui_toggle_settings settings = new();

        internal static Ui_toggle_settings Get_snapshot()
        {
            lock (Sync_root)
            {
                return new Ui_toggle_settings
                {
                    Build_json_file = settings.Build_json_file,
                    Apply_reed_solomon_for_json = settings.Apply_reed_solomon_for_json,
                    Json_transfer_directory_path = Normalize_json_transfer_directory_path(settings.Json_transfer_directory_path),
                    Auto_sender_key_generation = settings.Auto_sender_key_generation,
                    Enable_round_cipher = settings.Enable_round_cipher,
                    Encryption_core = settings.Encryption_core
                };
            }
        }

        internal static void Save(Ui_toggle_settings input)
        {
            ArgumentNullException.ThrowIfNull(input);

            lock (Sync_root)
            {
                settings.Build_json_file = input.Build_json_file;
                settings.Apply_reed_solomon_for_json = input.Apply_reed_solomon_for_json;
                settings.Json_transfer_directory_path = Normalize_json_transfer_directory_path(input.Json_transfer_directory_path);
                settings.Auto_sender_key_generation = input.Auto_sender_key_generation;
                settings.Enable_round_cipher = input.Enable_round_cipher;
                settings.Encryption_core = input.Encryption_core;
            }
        }

        static string Normalize_json_transfer_directory_path(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return Ui_toggle_settings.Build_default_json_directory_path();

            return Environment.ExpandEnvironmentVariables(value.Trim());
        }
    }
}
