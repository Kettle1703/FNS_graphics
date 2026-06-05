using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using OpenGost.Security.Cryptography;

namespace FNS_rebuild
{
    internal sealed class Kuznyechik_strategy : IStrategy
    {
        const byte Packet_version = 1;
        const int Iv_bytes = 16;
        const int Key_bytes = 32;

        public string Encrypt(string input, Cipher_options options)
        {
            options ??= Cipher_options.Default;

            byte[] key = Derive_key(options.Key);
            byte[] iv = RandomNumberGenerator.GetBytes(Iv_bytes);
            byte[] source_bytes = Encoding.UTF8.GetBytes(input ?? string.Empty);
            byte[] encrypted = Transform(source_bytes, key, iv, encrypt: true);

            using MemoryStream packet = new();
            packet.WriteByte(Packet_version);
            packet.WriteByte((byte)iv.Length);
            packet.Write(iv, 0, iv.Length);
            packet.Write(encrypted, 0, encrypted.Length);

            return Base64_url_codec.Encode(packet.ToArray());
        }

        public string Decrypt(string input, Cipher_options options)
        {
            options ??= Cipher_options.Default;

            if (!Base64_url_codec.Try_decode(input, out byte[] packet))
                throw new CryptographicException("Шифротекст Кузнечика должен быть в формате Base64/Base64URL.");

            if (packet.Length < 2)
                throw new CryptographicException("Шифротекст Кузнечика повреждён.");

            byte version = packet[0];
            if (version != Packet_version)
                throw new CryptographicException($"Неподдерживаемая версия пакета Кузнечика: {version}.");

            int iv_length = packet[1];
            if (iv_length != Iv_bytes || packet.Length < 2 + iv_length)
                throw new CryptographicException("Некорректная структура IV в пакете Кузнечика.");

            byte[] iv = new byte[iv_length];
            Array.Copy(packet, 2, iv, 0, iv_length);

            int ciphertext_length = packet.Length - 2 - iv_length;
            byte[] ciphertext = new byte[ciphertext_length];
            Array.Copy(packet, 2 + iv_length, ciphertext, 0, ciphertext_length);

            byte[] key = Derive_key(options.Key);
            byte[] decrypted = Transform(ciphertext, key, iv, encrypt: false);
            return Encoding.UTF8.GetString(decrypted);
        }

        static byte[] Derive_key(string? key_material)
        {
            string material = key_material ?? string.Empty;
            if (material.Length == 0)
                throw new CryptographicException("Для Кузнечика требуется ключевой материал.");

            return SHA256.HashData(Encoding.UTF8.GetBytes(material));
        }

        static byte[] Transform(byte[] input, byte[] key, byte[] iv, bool encrypt)
        {
            using Grasshopper algorithm = Grasshopper.Create();
            algorithm.Mode = CipherMode.CBC;
            algorithm.Padding = PaddingMode.PKCS7;
            algorithm.KeySize = Key_bytes * 8;
            algorithm.BlockSize = Iv_bytes * 8;

            using ICryptoTransform transform = encrypt
                ? algorithm.CreateEncryptor(key, iv)
                : algorithm.CreateDecryptor(key, iv);

            return transform.TransformFinalBlock(input, 0, input.Length);
        }
    }
}
