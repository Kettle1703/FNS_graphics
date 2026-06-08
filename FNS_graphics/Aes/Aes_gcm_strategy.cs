using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FNS_rebuild
{
    internal sealed class Aes_gcm_strategy : IStrategy
    {
        const byte Packet_version = 1;
        const int Key_bytes = 32;
        const int Nonce_bytes = 12;
        const int Tag_bytes = 16;

        public string Encrypt(string input, Cipher_options options)
        {
            options ??= Cipher_options.Default;

            byte[] key = Derive_key(options.Key);
            byte[] nonce = Build_nonce(options);
            byte[] source_bytes = Encoding.UTF8.GetBytes(input ?? string.Empty);
            byte[] ciphertext = new byte[source_bytes.Length];
            byte[] tag = new byte[Tag_bytes];

            using AesGcm aes = new(key, Tag_bytes);
            aes.Encrypt(nonce, source_bytes, ciphertext, tag);

            using MemoryStream packet = new();
            packet.WriteByte(Packet_version);
            packet.WriteByte((byte)nonce.Length);
            packet.WriteByte((byte)tag.Length);
            packet.Write(nonce, 0, nonce.Length);
            packet.Write(tag, 0, tag.Length);
            packet.Write(ciphertext, 0, ciphertext.Length);

            return Base64_url_codec.Encode(packet.ToArray());
        }

        public string Decrypt(string input, Cipher_options options)
        {
            options ??= Cipher_options.Default;

            if (!Base64_url_codec.Try_decode(input, out byte[] packet))
                throw new CryptographicException("Шифротекст AES-GCM должен быть в формате Base64/Base64URL.");

            if (packet.Length < 3)
                throw new CryptographicException("Шифротекст AES-GCM повреждён.");

            byte version = packet[0];
            if (version != Packet_version)
                throw new CryptographicException($"Неподдерживаемая версия пакета AES-GCM: {version}.");

            int nonce_length = packet[1];
            int tag_length = packet[2];
            if (nonce_length != Nonce_bytes || tag_length != Tag_bytes || packet.Length < 3 + nonce_length + tag_length)
                throw new CryptographicException("Некорректная структура nonce/tag в пакете AES-GCM.");

            byte[] nonce = new byte[nonce_length];
            byte[] tag = new byte[tag_length];
            Array.Copy(packet, 3, nonce, 0, nonce_length);
            Array.Copy(packet, 3 + nonce_length, tag, 0, tag_length);

            int ciphertext_offset = 3 + nonce_length + tag_length;
            int ciphertext_length = packet.Length - ciphertext_offset;
            byte[] ciphertext = new byte[ciphertext_length];
            Array.Copy(packet, ciphertext_offset, ciphertext, 0, ciphertext_length);

            byte[] key = Derive_key(options.Key);
            byte[] plaintext = new byte[ciphertext.Length];

            using AesGcm aes = new(key, Tag_bytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            return Encoding.UTF8.GetString(plaintext);
        }

        static byte[] Derive_key(string? key_material)
        {
            string material = key_material ?? string.Empty;
            if (material.Length == 0)
                throw new CryptographicException("Для AES-GCM требуется ключевой материал.");

            return SHA256.HashData(Encoding.UTF8.GetBytes(material));
        }

        static byte[] Build_nonce(Cipher_options options)
        {
            if (options.Fixed_message_nonce is null)
                return RandomNumberGenerator.GetBytes(Nonce_bytes);

            if (options.Fixed_message_nonce.Length == Nonce_bytes)
            {
                byte[] nonce = new byte[Nonce_bytes];
                Array.Copy(options.Fixed_message_nonce, nonce, nonce.Length);
                return nonce;
            }

            byte[] expanded = SHA256.HashData(options.Fixed_message_nonce);
            byte[] result = new byte[Nonce_bytes];
            Array.Copy(expanded, result, result.Length);
            return result;
        }
    }
}
