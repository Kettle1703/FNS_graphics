using System;
using System.IO;
using System.Security.Cryptography;
using FNS_rebuild;

namespace FNS_graphics
{
    internal static class Receiver_key_store
    {
        const string Private_key_file_name = "receiver_ecdh_private.pk8.b64";
        const string Public_key_file_name = "receiver_ecdh_public.spki.b64";

        internal static readonly string Default_storage_directory_path = App_storage_paths.Crypto_directory_path;

        internal static readonly string Default_private_key_path = Path.Combine(Default_storage_directory_path, Private_key_file_name);
        internal static readonly string Default_public_key_path = Path.Combine(Default_storage_directory_path, Public_key_file_name);

        internal static ECDiffieHellman LoadOrCreateDefault()
        {
            App_storage_paths.Ensure_crypto_directory_exists();
            return LoadOrCreate(Default_private_key_path, Default_public_key_path);
        }

        internal static string LoadOrCreateDefaultPublicKeyBase64()
        {
            using ECDiffieHellman receiver_private_key = LoadOrCreateDefault();
            return Base64_url_codec.Encode(receiver_private_key.ExportSubjectPublicKeyInfo());
        }

        internal static string RegenerateDefault()
        {
            App_storage_paths.Ensure_crypto_directory_exists();

            using ECDiffieHellman receiver = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            string private_key = Base64_url_codec.Encode(receiver.ExportPkcs8PrivateKey());
            string public_key = Base64_url_codec.Encode(receiver.ExportSubjectPublicKeyInfo());

            File.WriteAllText(Default_private_key_path, private_key);
            File.WriteAllText(Default_public_key_path, public_key);

            return public_key;
        }

        internal static bool Try_save_default_public_key_if_matches_private(
            string public_key_base64,
            out string error_message)
        {
            error_message = string.Empty;
            string normalized_public_key = Base64_url_codec.Canonicalize_if_possible(public_key_base64);
            if (!Base64_url_codec.Try_decode(normalized_public_key, out byte[] input_public_key_bytes))
            {
                error_message = "Публичный ключ получателя ECDH должен быть в формате Base64/Base64URL.";
                return false;
            }

            try
            {
                using ECDiffieHellman public_holder = ECDiffieHellman.Create();
                public_holder.ImportSubjectPublicKeyInfo(input_public_key_bytes, out int public_read);
                if (public_read != input_public_key_bytes.Length)
                {
                    error_message = "Публичный ключ получателя ECDH прочитан не полностью.";
                    return false;
                }

                using ECDiffieHellman private_key = LoadOrCreateDefault();
                string actual_public_key = Base64_url_codec.Encode(private_key.ExportSubjectPublicKeyInfo());
                string input_public_key = Base64_url_codec.Encode(input_public_key_bytes);
                if (!string.Equals(input_public_key, actual_public_key, StringComparison.Ordinal))
                {
                    error_message = "Указанный публичный ключ ECDH не соответствует локальному приватному ключу получателя. Такой ключ нельзя сохранить как ваш, иначе входящие пакеты не будут расшифровываться.";
                    return false;
                }

                File.WriteAllText(Default_public_key_path, actual_public_key);
                return true;
            }
            catch (Exception ex)
            {
                error_message = $"Не удалось проверить публичный ключ получателя ECDH: {ex.Message}";
                return false;
            }
        }

        internal static ECDiffieHellman LoadOrCreate(string private_key_path, string public_key_path)
        {
            // Загружает существующий приватный ключ получателя или создаёт новый.
            if (File.Exists(private_key_path))
            {
                string private_b64 = File.ReadAllText(private_key_path);
                if (!Base64_url_codec.Try_decode(private_b64, out byte[] private_bytes))
                    throw new CryptographicException("Файл приватного ключа получателя содержит некорректный Base64/Base64URL.");

                ECDiffieHellman imported = ECDiffieHellman.Create();
                imported.ImportPkcs8PrivateKey(private_bytes, out int read);
                if (read != private_bytes.Length)
                    throw new CryptographicException("Не удалось полностью прочитать приватный ECDH-ключ получателя.");

                if (!File.Exists(public_key_path))
                {
                    byte[] public_bytes = imported.ExportSubjectPublicKeyInfo();
                    File.WriteAllText(public_key_path, Base64_url_codec.Encode(public_bytes));
                }

                return imported;
            }

            ECDiffieHellman created = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] private_key = created.ExportPkcs8PrivateKey();
            byte[] public_key = created.ExportSubjectPublicKeyInfo();

            File.WriteAllText(private_key_path, Base64_url_codec.Encode(private_key));
            File.WriteAllText(public_key_path, Base64_url_codec.Encode(public_key));

            return created;
        }
    }
}
