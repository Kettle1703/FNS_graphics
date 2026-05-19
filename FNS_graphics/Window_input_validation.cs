using System;
using FNS_rebuild;

namespace FNS_graphics
{
    internal sealed class Encrypt_request
    {
        internal string Source_text { get; }
        internal byte[] Receiver_public_spki { get; }
        internal Cipher_options Options { get; }

        internal Encrypt_request(string source_text, byte[] receiver_public_spki, Cipher_options options)
        {
            Source_text = source_text;
            Receiver_public_spki = receiver_public_spki;
            Options = options;
        }
    }

    internal static class Window_input_validation
    {
        internal static bool TryBuildEncryptRequest(
            string? source_text,
            string? receiver_public_base64,
            byte[] default_receiver_public_spki,
            int block_plain_text_length,
            string auto_placeholder,
            out Encrypt_request request,
            out string error_message)
        {
            // Проверяет и собирает данные для шифрования.
            string source = source_text ?? string.Empty;
            if (source.Length == 0)
            {
                request = null!;
                error_message = "Введите исходный текст для шифрования.";
                return false;
            }

            string receiver_public_text = receiver_public_base64?.Trim() ?? string.Empty;
            byte[] receiver_public_spki;
            if (receiver_public_text.Length == 0 || receiver_public_text == auto_placeholder)
            {
                receiver_public_spki = default_receiver_public_spki;
            }
            else if (!TryDecodeBase64(receiver_public_text, out receiver_public_spki))
            {
                request = null!;
                error_message = "Публичный ключ получателя должен быть в формате Base64.";
                return false;
            }

            Cipher_options options = new()
            {
                Block_plain_text_length = block_plain_text_length,
                Key = string.Empty
            };

            request = new Encrypt_request(source, receiver_public_spki, options);
            error_message = string.Empty;
            return true;
        }

        internal static bool TryBuildDecryptPacket(
            string? ciphertext_text,
            string? sender_public_key_text,
            string? encrypted_symmetric_key_text,
            int block_plain_text_length,
            string auto_placeholder,
            out Hybrid_cipher_package packet,
            out string error_message)
        {
            // Проверяет и собирает пакет для дешифрования.
            string ciphertext = ciphertext_text ?? string.Empty;
            string sender_public_key = sender_public_key_text?.Trim() ?? string.Empty;
            string encrypted_symmetric_key = encrypted_symmetric_key_text?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(ciphertext) || ciphertext.StartsWith("<", StringComparison.Ordinal))
            {
                packet = null!;
                error_message = "Поле шифротекста не заполнено.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(sender_public_key) || sender_public_key == auto_placeholder)
            {
                packet = null!;
                error_message = "Поле ключа отправителя не заполнено.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(encrypted_symmetric_key) || encrypted_symmetric_key == auto_placeholder)
            {
                packet = null!;
                error_message = "Поле защищённого сеансового ключа не заполнено.";
                return false;
            }

            // Валидирует Base64-поля заранее, чтобы не использовать исключения как рабочий сценарий.
            if (!IsValidBase64(sender_public_key) || !IsValidBase64(encrypted_symmetric_key))
            {
                packet = null!;
                error_message = "Ключи пакета должны быть в формате Base64.";
                return false;
            }

            packet = new Hybrid_cipher_package
            {
                Ciphertext = ciphertext,
                Ephemeral_public_key = sender_public_key,
                Encrypted_symmetric_key = encrypted_symmetric_key,
                Block_plain_text_length = block_plain_text_length,
                Curve_id = Hybrid_fns_cryptosystem.Curve_id_nist_p256
            };

            error_message = string.Empty;
            return true;
        }

        static bool IsValidBase64(string encoded)
        {
            // Проверяет корректность Base64-строки без исключений.
            return TryDecodeBase64(encoded, out _);
        }

        static bool TryDecodeBase64(string encoded, out byte[] bytes)
        {
            // Преобразует Base64-строку без исключений.
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
    }
}
