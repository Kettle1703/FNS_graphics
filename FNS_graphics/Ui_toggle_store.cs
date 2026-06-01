using System;

namespace FNS_graphics
{
    internal sealed class Ui_toggle_settings
    {
        public bool Build_json_file { get; set; } = true;
        public bool Apply_reed_solomon_for_json { get; set; } = true;
        public bool Auto_sender_key_generation { get; set; } = true;
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
                    Auto_sender_key_generation = settings.Auto_sender_key_generation
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
                settings.Auto_sender_key_generation = input.Auto_sender_key_generation;
            }
        }
    }
}

