using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FNS_rebuild;

namespace FNS_graphics
{
    internal sealed class Sender_signing_key_entry
    {
        public string Public_key { get; set; } = string.Empty;
        public string Private_key_pkcs8 { get; set; } = string.Empty;
    }

    internal sealed class Digital_signature_settings
    {
        public bool Sign_ciphertext { get; set; } = true;

        // Legacy поле оставлено для совместимости со старым файлом настроек.
        public string Sender_long_term_public_key { get; set; } = string.Empty;

        public string Active_sender_signing_public_key { get; set; } = string.Empty;
        public List<Sender_signing_key_entry> Own_sender_signing_keys { get; set; } = [];
        public List<string> Trusted_sender_long_term_public_keys { get; set; } = [];
    }

    internal static class Digital_signature_store
    {
        static readonly object Sync_root = new();

        static readonly string Storage_directory_path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FNS_graphics",
            "crypto");

        static readonly string Settings_path = Path.Combine(Storage_directory_path, "digital_signature_settings.json");
        static readonly string Legacy_sender_private_key_path = Path.Combine(Storage_directory_path, "sender_long_term_signing_private.pk8.b64");
        static readonly string Legacy_sender_public_key_path = Path.Combine(Storage_directory_path, "sender_long_term_signing_public.spki.b64");

        static readonly JsonSerializerOptions Json_options = new()
        {
            WriteIndented = true
        };

        static bool settings_loaded;
        static Digital_signature_settings settings = new();

        internal static Digital_signature_settings Get_settings_snapshot()
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();
                return Clone(settings);
            }
        }

        internal static void Save_settings(Digital_signature_settings input)
        {
            ArgumentNullException.ThrowIfNull(input);

            lock (Sync_root)
            {
                Ensure_settings_loaded();

                settings.Sign_ciphertext = input.Sign_ciphertext;
                settings.Own_sender_signing_keys = Normalize_sender_signing_key_list(input.Own_sender_signing_keys);
                settings.Active_sender_signing_public_key = Normalize_base64_text(input.Active_sender_signing_public_key);
                settings.Trusted_sender_long_term_public_keys = Normalize_key_list(input.Trusted_sender_long_term_public_keys);

                Ensure_active_sender_signing_key_selected();
                settings.Sender_long_term_public_key = settings.Active_sender_signing_public_key;

                Save_settings_file();
            }
        }

        internal static Sender_signing_key_entry Generate_sender_long_term_key_pair_entry()
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();
                return Generate_new_signing_key_pair_entry();
            }
        }

        internal static bool Try_sign_cipher_package(
            Hybrid_cipher_package packet,
            out string signature_base64,
            out string error_message)
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();

                signature_base64 = string.Empty;
                error_message = string.Empty;

                if (!settings.Sign_ciphertext)
                    return true;

                if (!Try_build_canonical_package_payload(packet, out byte[] payload, out error_message))
                    return false;

                if (!Try_get_active_sender_private_key(out ECDsa sender_private_key, out error_message))
                    return false;

                using (sender_private_key)
                {
                    byte[] signature = sender_private_key.SignData(payload, HashAlgorithmName.SHA256);
                    signature_base64 = Convert.ToBase64String(signature);
                    return true;
                }
            }
        }

        internal static bool Try_verify_cipher_package_signature_with_trusted_keys(
            Hybrid_cipher_package packet,
            IReadOnlyList<string>? trusted_sender_long_term_public_keys,
            out string error_message)
        {
            error_message = string.Empty;

            if (packet is null)
            {
                error_message = "Пакет шифрования не задан.";
                return false;
            }

            List<string> normalized_keys = Normalize_key_list(trusted_sender_long_term_public_keys);
            if (normalized_keys.Count == 0)
            {
                error_message = "Список доверенных публичных ключей отправителя пуст.";
                return false;
            }

            if (!Try_build_canonical_package_payload(packet, out byte[] payload, out error_message))
                return false;

            string normalized_signature = Normalize_base64_text(packet.Ephemeral_public_key_signature);
            if (!Try_decode_base64(normalized_signature, out byte[] signature))
            {
                error_message = "Подпись пакета некорректна: ожидается Base64-строка.";
                return false;
            }

            int valid_key_count = 0;
            foreach (string trusted_key in normalized_keys)
            {
                if (!Try_decode_base64(trusted_key, out byte[] sender_public_key_spki))
                    continue;

                valid_key_count++;

                if (Try_verify_signature_payload_with_sender_key(payload, signature, sender_public_key_spki))
                    return true;
            }

            if (valid_key_count == 0)
            {
                error_message = "В списке доверенных ключей нет ни одного корректного ключа (ожидается Base64 SPKI).";
                return false;
            }

            error_message = "Проверка подписи не пройдена: пакет изменён или подписан недоверенным ключом.";
            return false;
        }

        static bool Try_build_canonical_package_payload(
            Hybrid_cipher_package packet,
            out byte[] payload,
            out string error_message)
        {
            payload = [];
            error_message = string.Empty;

            if (packet is null)
            {
                error_message = "Пакет шифрования не задан.";
                return false;
            }

            string ciphertext = packet.Ciphertext ?? string.Empty;
            string normalized_ephemeral_key = Normalize_base64_text(packet.Ephemeral_public_key);
            string normalized_encrypted_symmetric_key = Normalize_base64_text(packet.Encrypted_symmetric_key);

            if (!Try_decode_base64(normalized_ephemeral_key, out _))
            {
                error_message = "Публичный одноразовый ключ отправителя в пакете некорректен: ожидается Base64-строка SPKI.";
                return false;
            }

            if (!Try_decode_base64(normalized_encrypted_symmetric_key, out _))
            {
                error_message = "Поле защищённого симметрического ключа в пакете некорректно: ожидается Base64-строка.";
                return false;
            }

            using MemoryStream stream = new();
            using (BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true))
            {
                Write_utf8_field(writer, "FNS_GRAPHICS_PACKET_SIGNATURE_V1");
                writer.Write(packet.Curve_id);
                writer.Write(packet.Block_plain_text_length);
                Write_utf8_field(writer, ciphertext);
                Write_utf8_field(writer, normalized_encrypted_symmetric_key);
                Write_utf8_field(writer, normalized_ephemeral_key);
                writer.Flush();
            }

            payload = stream.ToArray();
            return true;
        }

        static void Write_utf8_field(BinaryWriter writer, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }

        static bool Try_verify_signature_payload_with_sender_key(byte[] payload, byte[] signature, byte[] sender_public_key_spki)
        {
            try
            {
                using ECDsa sender_public_signing_key = ECDsa.Create();
                sender_public_signing_key.ImportSubjectPublicKeyInfo(sender_public_key_spki, out int read);
                if (read != sender_public_key_spki.Length)
                    return false;

                return sender_public_signing_key.VerifyData(payload, signature, HashAlgorithmName.SHA256);
            }
            catch
            {
                return false;
            }
        }

        static void Ensure_settings_loaded()
        {
            if (settings_loaded)
                return;

            Ensure_storage_directory_exists();

            settings = new Digital_signature_settings();

            if (File.Exists(Settings_path))
            {
                try
                {
                    string json = File.ReadAllText(Settings_path);
                    Digital_signature_settings? parsed = JsonSerializer.Deserialize<Digital_signature_settings>(json);
                    if (parsed is not null)
                    {
                        settings.Sign_ciphertext = parsed.Sign_ciphertext;
                        settings.Sender_long_term_public_key = Normalize_base64_text(parsed.Sender_long_term_public_key);
                        settings.Active_sender_signing_public_key = Normalize_base64_text(parsed.Active_sender_signing_public_key);
                        settings.Own_sender_signing_keys = Normalize_sender_signing_key_list(parsed.Own_sender_signing_keys);
                        settings.Trusted_sender_long_term_public_keys = Normalize_key_list(parsed.Trusted_sender_long_term_public_keys);
                    }
                }
                catch
                {
                    settings = new Digital_signature_settings();
                }
            }

            Try_migrate_legacy_sender_signing_key();
            Ensure_default_sender_signing_key_pair();
            Ensure_active_sender_signing_key_selected();

            settings.Sender_long_term_public_key = settings.Active_sender_signing_public_key;
            Save_settings_file();
            settings_loaded = true;
        }

        static void Try_migrate_legacy_sender_signing_key()
        {
            if (settings.Own_sender_signing_keys.Count > 0)
                return;

            string legacy_public_key = settings.Sender_long_term_public_key;
            if (legacy_public_key.Length == 0)
                legacy_public_key = Load_public_key_from_file(Legacy_sender_public_key_path);

            if (legacy_public_key.Length == 0)
                return;

            if (!File.Exists(Legacy_sender_private_key_path))
                return;

            string legacy_private_key = Normalize_base64_text(File.ReadAllText(Legacy_sender_private_key_path));
            if (!Try_decode_base64(legacy_private_key, out byte[] private_key_bytes))
                return;

            try
            {
                using ECDsa candidate = ECDsa.Create();
                candidate.ImportPkcs8PrivateKey(private_key_bytes, out int read);
                if (read != private_key_bytes.Length)
                    return;
            }
            catch
            {
                return;
            }

            settings.Own_sender_signing_keys =
            [
                new Sender_signing_key_entry
                {
                    Public_key = legacy_public_key,
                    Private_key_pkcs8 = legacy_private_key
                }
            ];

            settings.Active_sender_signing_public_key = legacy_public_key;
        }

        static void Ensure_default_sender_signing_key_pair()
        {
            if (settings.Own_sender_signing_keys.Count > 0)
                return;

            // Для демонстрации/тестирования на первом запуске генерируется первая пара отправителя.
            Sender_signing_key_entry generated = Generate_new_signing_key_pair_entry();
            settings.Own_sender_signing_keys = [generated];
            settings.Active_sender_signing_public_key = generated.Public_key;
        }

        static Sender_signing_key_entry Generate_new_signing_key_pair_entry()
        {
            using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] private_key = signer.ExportPkcs8PrivateKey();
            byte[] public_key = signer.ExportSubjectPublicKeyInfo();

            return new Sender_signing_key_entry
            {
                Private_key_pkcs8 = Convert.ToBase64String(private_key),
                Public_key = Convert.ToBase64String(public_key)
            };
        }

        static string Load_public_key_from_file(string public_key_path)
        {
            if (!File.Exists(public_key_path))
                return string.Empty;

            try
            {
                return Normalize_base64_text(File.ReadAllText(public_key_path));
            }
            catch
            {
                return string.Empty;
            }
        }

        static void Save_settings_file()
        {
            settings.Own_sender_signing_keys = Normalize_sender_signing_key_list(settings.Own_sender_signing_keys);
            settings.Trusted_sender_long_term_public_keys = Normalize_key_list(settings.Trusted_sender_long_term_public_keys);
            Ensure_active_sender_signing_key_selected();
            settings.Sender_long_term_public_key = settings.Active_sender_signing_public_key;

            string json = JsonSerializer.Serialize(settings, Json_options);
            File.WriteAllText(Settings_path, json);
        }

        static bool Try_get_active_sender_private_key(out ECDsa sender_private_key, out string error_message)
        {
            sender_private_key = null!;
            error_message = string.Empty;

            Ensure_active_sender_signing_key_selected();
            if (settings.Own_sender_signing_keys.Count == 0)
            {
                error_message = "Список собственных ключей подписи отправителя пуст.";
                return false;
            }

            Sender_signing_key_entry? active_entry = null;
            foreach (Sender_signing_key_entry item in settings.Own_sender_signing_keys)
            {
                if (string.Equals(item.Public_key, settings.Active_sender_signing_public_key, StringComparison.Ordinal))
                {
                    active_entry = item;
                    break;
                }
            }

            if (active_entry is null)
            {
                error_message = "Не выбран активный ключ подписи отправителя.";
                return false;
            }

            if (!Try_decode_base64(active_entry.Private_key_pkcs8, out byte[] private_key_bytes))
            {
                error_message = "Активный приватный ключ подписи отправителя повреждён (ожидается Base64 PKCS8).";
                return false;
            }

            try
            {
                ECDsa loaded_key = ECDsa.Create();
                loaded_key.ImportPkcs8PrivateKey(private_key_bytes, out int read);
                if (read != private_key_bytes.Length)
                {
                    loaded_key.Dispose();
                    error_message = "Активный приватный ключ подписи отправителя прочитан не полностью.";
                    return false;
                }

                sender_private_key = loaded_key;
                return true;
            }
            catch (Exception ex)
            {
                error_message = $"Ошибка загрузки активного приватного ключа подписи отправителя: {ex.Message}";
                return false;
            }
        }

        static void Ensure_active_sender_signing_key_selected()
        {
            settings.Active_sender_signing_public_key = Normalize_base64_text(settings.Active_sender_signing_public_key);

            if (settings.Active_sender_signing_public_key.Length > 0)
            {
                foreach (Sender_signing_key_entry key in settings.Own_sender_signing_keys)
                {
                    if (string.Equals(key.Public_key, settings.Active_sender_signing_public_key, StringComparison.Ordinal))
                        return;
                }
            }

            settings.Active_sender_signing_public_key = settings.Own_sender_signing_keys.Count > 0
                ? settings.Own_sender_signing_keys[0].Public_key
                : string.Empty;
        }

        static string Normalize_base64_text(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string source = value.Trim();
            StringBuilder builder = new(source.Length);
            foreach (char ch in source)
            {
                if (!char.IsWhiteSpace(ch))
                    builder.Append(ch);
            }

            return builder.ToString();
        }

        static List<string> Normalize_key_list(IEnumerable<string>? values)
        {
            List<string> result = [];
            if (values is null)
                return result;

            HashSet<string> seen = new(StringComparer.Ordinal);
            foreach (string? value in values)
            {
                string normalized = Normalize_base64_text(value);
                if (normalized.Length == 0)
                    continue;

                if (seen.Add(normalized))
                    result.Add(normalized);
            }

            return result;
        }

        static List<Sender_signing_key_entry> Normalize_sender_signing_key_list(IEnumerable<Sender_signing_key_entry>? values)
        {
            List<Sender_signing_key_entry> result = [];
            if (values is null)
                return result;

            HashSet<string> seen_public_keys = new(StringComparer.Ordinal);
            foreach (Sender_signing_key_entry? value in values)
            {
                if (value is null)
                    continue;

                string public_key = Normalize_base64_text(value.Public_key);
                string private_key = Normalize_base64_text(value.Private_key_pkcs8);
                if (public_key.Length == 0 || private_key.Length == 0)
                    continue;

                if (!Try_decode_base64(public_key, out _))
                    continue;

                if (!Try_decode_base64(private_key, out byte[] private_key_bytes))
                    continue;

                try
                {
                    using ECDsa candidate = ECDsa.Create();
                    candidate.ImportPkcs8PrivateKey(private_key_bytes, out int read);
                    if (read != private_key_bytes.Length)
                        continue;
                }
                catch
                {
                    continue;
                }

                if (!seen_public_keys.Add(public_key))
                    continue;

                result.Add(new Sender_signing_key_entry
                {
                    Public_key = public_key,
                    Private_key_pkcs8 = private_key
                });
            }

            return result;
        }

        static bool Try_decode_base64(string encoded, out byte[] bytes)
        {
            int buffer_length = ((encoded.Length + 3) / 4) * 3;
            byte[] buffer = new byte[buffer_length];

            if (!Convert.TryFromBase64String(encoded, buffer, out int written))
            {
                bytes = [];
                return false;
            }

            if (written == buffer_length)
            {
                bytes = buffer;
                return true;
            }

            bytes = new byte[written];
            Array.Copy(buffer, bytes, written);
            return true;
        }

        static Digital_signature_settings Clone(Digital_signature_settings source)
        {
            return new Digital_signature_settings
            {
                Sign_ciphertext = source.Sign_ciphertext,
                Sender_long_term_public_key = source.Sender_long_term_public_key,
                Active_sender_signing_public_key = source.Active_sender_signing_public_key,
                Own_sender_signing_keys = [.. source.Own_sender_signing_keys.ConvertAll(static value => new Sender_signing_key_entry
                {
                    Public_key = value.Public_key,
                    Private_key_pkcs8 = value.Private_key_pkcs8
                })],
                Trusted_sender_long_term_public_keys = [.. source.Trusted_sender_long_term_public_keys]
            };
        }

        static void Ensure_storage_directory_exists()
        {
            if (!Directory.Exists(Storage_directory_path))
                Directory.CreateDirectory(Storage_directory_path);
        }

    }
}
