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

    internal sealed class Recipient_key_link_entry
    {
        public string Link_id { get; set; } = string.Empty;
        public string Recipient_name { get; set; } = string.Empty;
        public string Sender_signing_private_key_pkcs8 { get; set; } = string.Empty;
        public string Sender_signing_public_key_spki { get; set; } = string.Empty;
        public string Trusted_sender_signing_public_key { get; set; } = string.Empty;
        public string Receiver_hybrid_public_key { get; set; } = string.Empty;
    }

    internal sealed class Digital_signature_settings
    {
        public bool Sign_ciphertext { get; set; } = true;
        public List<Recipient_key_link_entry> Recipient_links { get; set; } = [];
        public string Active_recipient_link_id { get; set; } = string.Empty;

        // Основная форма пока использует эти поля.
        public string Active_sender_signing_public_key { get; set; } = string.Empty;
        public List<Sender_signing_key_entry> Own_sender_signing_keys { get; set; } = [];
        public List<string> Trusted_sender_long_term_public_keys { get; set; } = [];
    }

    internal static class Digital_signature_store
    {
        static readonly object Sync_root = new();

        const string Settings_file_name = "digital_signature_settings.json";

        static readonly string Storage_directory_path = App_storage_paths.Crypto_directory_path;

        static readonly string Settings_path = Path.Combine(Storage_directory_path, Settings_file_name);

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

        internal static bool Has_configured_recipient_links()
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();
                return settings.Recipient_links.Count > 0;
            }
        }

        internal static bool Try_get_active_recipient_link_snapshot(
            out Recipient_key_link_entry active_link,
            out string error_message)
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();

                Recipient_key_link_entry? link = Find_active_recipient_link();
                if (link is null)
                {
                    active_link = null!;
                    error_message = "Нет активной связи ключей получателя.";
                    return false;
                }

                active_link = Clone_recipient_link(link);
                error_message = string.Empty;
                return true;
            }
        }

        internal static void Save_settings(Digital_signature_settings input)
        {
            ArgumentNullException.ThrowIfNull(input);

            lock (Sync_root)
            {
                Ensure_settings_loaded();

                settings.Sign_ciphertext = input.Sign_ciphertext;
                settings.Recipient_links = Normalize_recipient_link_list(input.Recipient_links);
                settings.Active_recipient_link_id = Normalize_identifier(input.Active_recipient_link_id);

                Ensure_active_recipient_selected();
                Synchronize_compatibility_fields_from_active_recipient();
                Save_settings_file();
            }
        }

        internal static Recipient_key_link_entry Generate_recipient_key_link_entry(string? recipient_name = null)
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();

                HashSet<string> existing_names = new(StringComparer.Ordinal);
                foreach (Recipient_key_link_entry link in settings.Recipient_links)
                    existing_names.Add(link.Recipient_name);

                string normalized_name = Normalize_recipient_name(recipient_name);
                if (normalized_name.Length == 0)
                    normalized_name = Build_random_recipient_name();

                string unique_name = Ensure_unique_recipient_name(normalized_name, existing_names);
                Sender_signing_key_entry sender_signing = Generate_sender_signing_key_pair_entry();

                return new Recipient_key_link_entry
                {
                    Link_id = Guid.NewGuid().ToString("N"),
                    Recipient_name = unique_name,
                    Sender_signing_private_key_pkcs8 = sender_signing.Private_key_pkcs8,
                    Sender_signing_public_key_spki = sender_signing.Public_key,
                    Trusted_sender_signing_public_key = string.Empty,
                    Receiver_hybrid_public_key = string.Empty
                };
            }
        }

        internal static bool Try_get_sender_signing_public_key_from_private(
            string sender_signing_private_key_pkcs8,
            out string sender_signing_public_key_spki,
            out string error_message)
        {
            sender_signing_public_key_spki = string.Empty;
            error_message = string.Empty;

            string normalized_private = Normalize_base64_text(sender_signing_private_key_pkcs8);
            if (normalized_private.Length == 0)
            {
                error_message = "Приватный ключ подписи отправителя пуст.";
                return false;
            }

            if (!Try_decode_base64(normalized_private, out byte[] private_key_bytes))
            {
                error_message = "Приватный ключ подписи отправителя должен быть в формате Base64.";
                return false;
            }

            try
            {
                using ECDsa signer = ECDsa.Create();
                signer.ImportPkcs8PrivateKey(private_key_bytes, out int read);
                if (read != private_key_bytes.Length)
                {
                    error_message = "Приватный ключ подписи отправителя прочитан не полностью.";
                    return false;
                }

                sender_signing_public_key_spki = Base64_url_codec.Encode(signer.ExportSubjectPublicKeyInfo());
                return true;
            }
            catch
            {
                error_message = "Приватный ключ подписи отправителя не похож на корректный PKCS8-ключ ECDSA.";
                return false;
            }
        }

        internal static bool Try_validate_sender_signing_public_key(string sender_signing_public_key_spki, out string error_message)
        {
            if (Try_validate_ecdsa_public_key(sender_signing_public_key_spki))
            {
                error_message = string.Empty;
                return true;
            }

            error_message = "Публичный ключ подписи должен быть корректным SPKI-ключом ECDSA в формате Base64.";
            return false;
        }

        internal static bool Try_validate_receiver_hybrid_public_key(string receiver_hybrid_public_key_spki, out string error_message)
        {
            if (Try_validate_ecdh_public_key(receiver_hybrid_public_key_spki))
            {
                error_message = string.Empty;
                return true;
            }

            error_message = "Публичный ключ получателя для гибридного шифрования должен быть SPKI-ключом ECDH в формате Base64.";
            return false;
        }

        internal static bool Try_get_sender_signing_key_fingerprint(
            string sender_signing_public_key_spki,
            out string key_fingerprint,
            out string error_message)
        {
            key_fingerprint = string.Empty;
            error_message = string.Empty;

            string normalized_public_key = Normalize_base64_text(sender_signing_public_key_spki);
            if (normalized_public_key.Length == 0)
            {
                error_message = "Публичный ключ подписи отправителя пуст.";
                return false;
            }

            if (!Try_build_sender_signing_key_fingerprint_from_public_key(normalized_public_key, out key_fingerprint))
            {
                error_message = "Публичный ключ подписи отправителя должен быть корректным SPKI-ключом ECDSA в формате Base64.";
                return false;
            }

            return true;
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
                    signature_base64 = Base64_url_codec.Encode(signature);
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

        internal static bool Try_verify_cipher_package_signature_and_select_recipient_link(
            Hybrid_cipher_package packet,
            out Recipient_key_link_entry matched_link,
            out string error_message)
        {
            lock (Sync_root)
            {
                Ensure_settings_loaded();

                matched_link = null!;
                error_message = string.Empty;

                if (packet is null)
                {
                    error_message = "Пакет шифрования не задан.";
                    return false;
                }

                if (settings.Recipient_links.Count == 0)
                {
                    error_message = "Список связей ключей пуст.";
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

                string preferred_sender_signing_key_fingerprint = Normalize_key_fingerprint(packet.Sender_signing_key_fingerprint);
                List<Recipient_key_link_entry> candidates = Build_signature_verification_candidates(preferred_sender_signing_key_fingerprint);
                if (preferred_sender_signing_key_fingerprint.Length > 0 && candidates.Count == 0)
                {
                    error_message = "Для отпечатка ключа подписи отправителя из пакета не найдена подходящая связь.";
                    return false;
                }

                int valid_key_count = 0;
                foreach (Recipient_key_link_entry candidate in candidates)
                {
                    string trusted_sender_key = Normalize_base64_text(candidate.Trusted_sender_signing_public_key);
                    if (!Try_decode_base64(trusted_sender_key, out byte[] sender_public_key_spki))
                        continue;

                    valid_key_count++;
                    if (!Try_verify_signature_payload_with_sender_key(payload, signature, sender_public_key_spki))
                        continue;

                    Try_activate_recipient_link_for_runtime(candidate.Link_id);
                    matched_link = Clone_recipient_link(candidate);
                    error_message = string.Empty;
                    return true;
                }

                if (valid_key_count == 0)
                {
                    error_message = "В связях ключей нет ни одного корректного доверенного публичного ключа отправителя (ожидается Base64 SPKI).";
                    return false;
                }

                error_message = "Проверка подписи не пройдена: пакет изменён или подписан недоверенным ключом.";
                return false;
            }
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
            string normalized_sender_signing_key_fingerprint = Normalize_key_fingerprint(packet.Sender_signing_key_fingerprint);
            string encryption_core = Encryption_core_catalog.To_storage_id(packet.Encryption_core);

            if (!Try_decode_base64(normalized_ephemeral_key, out _))
            {
                error_message = "Публичный одноразовый ключ отправителя в пакете некорректен: ожидается Base64-строка SPKI.";
                return false;
            }

            if (!Try_decode_base64(normalized_encrypted_symmetric_key, out _))
            {
                error_message = "Поле публичной соли для восстановления симметричного ключа в пакете некорректно: ожидается Base64-строка.";
                return false;
            }

            if (normalized_sender_signing_key_fingerprint.Length > 0 &&
                !Is_valid_key_fingerprint(normalized_sender_signing_key_fingerprint))
            {
                error_message = "Отпечаток ключа подписи отправителя в пакете некорректен: ожидается HEX SHA-256.";
                return false;
            }

            using MemoryStream stream = new();
            using (BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true))
            {
                Write_utf8_field(writer, "FNS_GRAPHICS_PACKET_SIGNATURE_V4");
                writer.Write(packet.Curve_id);
                writer.Write(packet.Block_plain_text_length);
                writer.Write(packet.Round_cipher_enabled);
                Write_utf8_field(writer, encryption_core);
                Write_utf8_field(writer, ciphertext);
                Write_utf8_field(writer, normalized_encrypted_symmetric_key);
                Write_utf8_field(writer, normalized_ephemeral_key);
                Write_utf8_field(writer, normalized_sender_signing_key_fingerprint);
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

        static bool Try_build_sender_signing_key_fingerprint_from_public_key(string sender_signing_public_key_spki, out string key_fingerprint)
        {
            key_fingerprint = string.Empty;
            string normalized_public_key = Normalize_base64_text(sender_signing_public_key_spki);
            if (!Try_decode_base64(normalized_public_key, out byte[] key_bytes))
                return false;

            try
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(key_bytes, out int read);
                if (read != key_bytes.Length)
                    return false;
            }
            catch
            {
                return false;
            }

            key_fingerprint = Convert.ToHexString(SHA256.HashData(key_bytes));
            return true;
        }

        static List<Recipient_key_link_entry> Build_signature_verification_candidates(string preferred_sender_signing_key_fingerprint)
        {
            List<Recipient_key_link_entry> ordered = [];
            HashSet<string> seen_link_ids = new(StringComparer.Ordinal);

            if (preferred_sender_signing_key_fingerprint.Length == 0)
            {
                foreach (Recipient_key_link_entry link in settings.Recipient_links)
                {
                    if (seen_link_ids.Add(link.Link_id))
                        ordered.Add(link);
                }

                return ordered;
            }

            foreach (Recipient_key_link_entry link in settings.Recipient_links)
            {
                if (!Try_build_sender_signing_key_fingerprint_from_public_key(
                        link.Trusted_sender_signing_public_key,
                        out string link_fingerprint))
                {
                    continue;
                }

                if (!string.Equals(link_fingerprint, preferred_sender_signing_key_fingerprint, StringComparison.Ordinal))
                    continue;

                if (seen_link_ids.Add(link.Link_id))
                    ordered.Add(link);
            }

            return ordered;
        }

        static void Try_activate_recipient_link_for_runtime(string link_id)
        {
            string normalized_link_id = Normalize_identifier(link_id);
            if (normalized_link_id.Length == 0)
                return;

            if (string.Equals(settings.Active_recipient_link_id, normalized_link_id, StringComparison.Ordinal))
                return;

            settings.Active_recipient_link_id = normalized_link_id;
            Save_settings_file();
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
                        settings.Recipient_links = Normalize_recipient_link_list(parsed.Recipient_links);
                        settings.Active_recipient_link_id = Normalize_identifier(parsed.Active_recipient_link_id);
                    }
                }
                catch
                {
                    settings = new Digital_signature_settings();
                }
            }

            Ensure_active_recipient_selected();
            Synchronize_compatibility_fields_from_active_recipient();
            Save_settings_file();
            settings_loaded = true;
        }

        static void Ensure_active_recipient_selected()
        {
            settings.Active_recipient_link_id = Normalize_identifier(settings.Active_recipient_link_id);
            if (settings.Recipient_links.Count == 0)
            {
                settings.Active_recipient_link_id = string.Empty;
                return;
            }

            if (settings.Active_recipient_link_id.Length == 0)
            {
                settings.Active_recipient_link_id = settings.Recipient_links[0].Link_id;
                return;
            }

            foreach (Recipient_key_link_entry link in settings.Recipient_links)
            {
                if (string.Equals(link.Link_id, settings.Active_recipient_link_id, StringComparison.Ordinal))
                    return;
            }

            settings.Active_recipient_link_id = settings.Recipient_links[0].Link_id;
        }

        static Recipient_key_link_entry? Find_active_recipient_link()
        {
            Ensure_active_recipient_selected();
            if (settings.Active_recipient_link_id.Length == 0)
                return null;

            foreach (Recipient_key_link_entry link in settings.Recipient_links)
            {
                if (string.Equals(link.Link_id, settings.Active_recipient_link_id, StringComparison.Ordinal))
                    return link;
            }

            return null;
        }

        static void Synchronize_compatibility_fields_from_active_recipient()
        {
            Recipient_key_link_entry? active_link = Find_active_recipient_link();
            if (active_link is null)
            {
                settings.Active_sender_signing_public_key = string.Empty;
                settings.Own_sender_signing_keys = [];
                settings.Trusted_sender_long_term_public_keys = [];
                return;
            }

            string sender_public_key = Normalize_base64_text(active_link.Sender_signing_public_key_spki);
            if (Try_get_sender_signing_public_key_from_private(
                    active_link.Sender_signing_private_key_pkcs8,
                    out string sender_public_key_from_private,
                    out _))
            {
                if (sender_public_key.Length == 0)
                    sender_public_key = sender_public_key_from_private;

                settings.Active_sender_signing_public_key = sender_public_key;
                settings.Own_sender_signing_keys =
                [
                    new Sender_signing_key_entry
                    {
                        Public_key = sender_public_key,
                        Private_key_pkcs8 = active_link.Sender_signing_private_key_pkcs8
                    }
                ];
            }
            else
            {
                settings.Active_sender_signing_public_key = string.Empty;
                settings.Own_sender_signing_keys = [];
            }

            settings.Trusted_sender_long_term_public_keys = [Normalize_base64_text(active_link.Trusted_sender_signing_public_key)];
        }

        static void Save_settings_file()
        {
            settings.Recipient_links = Normalize_recipient_link_list(settings.Recipient_links);
            Ensure_active_recipient_selected();
            Synchronize_compatibility_fields_from_active_recipient();

            string json = JsonSerializer.Serialize(settings, Json_options);
            File.WriteAllText(Settings_path, json);
        }

        static bool Try_get_active_sender_private_key(out ECDsa sender_private_key, out string error_message)
        {
            sender_private_key = null!;
            error_message = string.Empty;

            Recipient_key_link_entry? active_link = Find_active_recipient_link();
            if (active_link is null)
            {
                error_message = "Нет активной связи ключей получателя.";
                return false;
            }

            if (!Try_decode_base64(active_link.Sender_signing_private_key_pkcs8, out byte[] private_key_bytes))
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

        static string Normalize_identifier(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            return value.Trim();
        }

        static string Normalize_recipient_name(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            return value.Trim();
        }

        static string Normalize_base64_text(string? value)
        {
            return Base64_url_codec.Canonicalize_if_possible(value);
        }

        static string Normalize_key_fingerprint(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string source = value.Trim();
            StringBuilder builder = new(source.Length);
            foreach (char ch in source)
            {
                if (!char.IsWhiteSpace(ch))
                    builder.Append(char.ToUpperInvariant(ch));
            }

            return builder.ToString();
        }

        static bool Is_valid_key_fingerprint(string value)
        {
            if (value.Length != 64)
                return false;

            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];
                bool is_digit = ch >= '0' && ch <= '9';
                bool is_hex_letter = ch >= 'A' && ch <= 'F';
                if (!is_digit && !is_hex_letter)
                    return false;
            }

            return true;
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

        static List<Recipient_key_link_entry> Normalize_recipient_link_list(IEnumerable<Recipient_key_link_entry>? values)
        {
            List<Recipient_key_link_entry> result = [];
            if (values is null)
                return result;

            HashSet<string> seen_ids = new(StringComparer.Ordinal);
            foreach (Recipient_key_link_entry? source in values)
            {
                if (source is null)
                    continue;

                string link_id = Normalize_identifier(source.Link_id);
                if (link_id.Length == 0 || !seen_ids.Add(link_id))
                {
                    link_id = Guid.NewGuid().ToString("N");
                    seen_ids.Add(link_id);
                }

                string recipient_name = Normalize_recipient_name(source.Recipient_name);
                if (recipient_name.Length == 0)
                    recipient_name = Build_random_recipient_name();

                result.Add(new Recipient_key_link_entry
                {
                    Link_id = link_id,
                    Recipient_name = recipient_name,
                    Sender_signing_private_key_pkcs8 = Normalize_base64_text(source.Sender_signing_private_key_pkcs8),
                    Sender_signing_public_key_spki = Normalize_base64_text(source.Sender_signing_public_key_spki),
                    Trusted_sender_signing_public_key = Normalize_base64_text(source.Trusted_sender_signing_public_key),
                    Receiver_hybrid_public_key = Normalize_base64_text(source.Receiver_hybrid_public_key)
                });
            }

            return result;
        }

        static string Ensure_unique_recipient_name(string candidate, HashSet<string> existing_names)
        {
            if (existing_names.Add(candidate))
                return candidate;

            while (true)
            {
                string generated = Build_random_recipient_name();
                if (existing_names.Add(generated))
                    return generated;
            }
        }

        static string Build_random_recipient_name()
        {
            Span<char> digits = stackalloc char[6];
            for (int i = 0; i < digits.Length; i++)
                digits[i] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));

            return $"Получатель_{new string(digits)}";
        }

        internal static Sender_signing_key_entry Generate_sender_signing_key_pair_entry()
        {
            using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new Sender_signing_key_entry
            {
                Private_key_pkcs8 = Base64_url_codec.Encode(signer.ExportPkcs8PrivateKey()),
                Public_key = Base64_url_codec.Encode(signer.ExportSubjectPublicKeyInfo())
            };
        }

        static bool Try_validate_ecdsa_public_key(string key_base64)
        {
            string normalized = Normalize_base64_text(key_base64);
            if (!Try_decode_base64(normalized, out byte[] key_bytes))
                return false;

            try
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(key_bytes, out int read);
                return read == key_bytes.Length;
            }
            catch
            {
                return false;
            }
        }

        static bool Try_validate_ecdh_public_key(string key_base64)
        {
            string normalized = Normalize_base64_text(key_base64);
            if (!Try_decode_base64(normalized, out byte[] key_bytes))
                return false;

            try
            {
                using ECDiffieHellman ecdh = ECDiffieHellman.Create();
                ecdh.ImportSubjectPublicKeyInfo(key_bytes, out int read);
                return read == key_bytes.Length;
            }
            catch
            {
                return false;
            }
        }

        static bool Try_decode_base64(string encoded, out byte[] bytes)
        {
            return Base64_url_codec.Try_decode(encoded, out bytes);
        }

        static Digital_signature_settings Clone(Digital_signature_settings source)
        {
            return new Digital_signature_settings
            {
                Sign_ciphertext = source.Sign_ciphertext,
                Recipient_links = [.. source.Recipient_links.ConvertAll(static link => new Recipient_key_link_entry
                {
                    Link_id = link.Link_id,
                    Recipient_name = link.Recipient_name,
                    Sender_signing_private_key_pkcs8 = link.Sender_signing_private_key_pkcs8,
                    Sender_signing_public_key_spki = link.Sender_signing_public_key_spki,
                    Trusted_sender_signing_public_key = link.Trusted_sender_signing_public_key,
                    Receiver_hybrid_public_key = link.Receiver_hybrid_public_key
                })],
                Active_recipient_link_id = source.Active_recipient_link_id,
                Active_sender_signing_public_key = source.Active_sender_signing_public_key,
                Own_sender_signing_keys = [.. source.Own_sender_signing_keys.ConvertAll(static key => new Sender_signing_key_entry
                {
                    Public_key = key.Public_key,
                    Private_key_pkcs8 = key.Private_key_pkcs8
                })],
                Trusted_sender_long_term_public_keys = [.. source.Trusted_sender_long_term_public_keys]
            };
        }

        static Recipient_key_link_entry Clone_recipient_link(Recipient_key_link_entry source)
        {
            return new Recipient_key_link_entry
            {
                Link_id = source.Link_id,
                Recipient_name = source.Recipient_name,
                Sender_signing_private_key_pkcs8 = source.Sender_signing_private_key_pkcs8,
                Sender_signing_public_key_spki = source.Sender_signing_public_key_spki,
                Trusted_sender_signing_public_key = source.Trusted_sender_signing_public_key,
                Receiver_hybrid_public_key = source.Receiver_hybrid_public_key
            };
        }

        static void Ensure_storage_directory_exists()
        {
            App_storage_paths.Ensure_crypto_directory_exists();
        }
    }
}
