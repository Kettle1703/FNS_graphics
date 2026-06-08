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
            byte[] iv = Build_iv(options);
            byte[] source_bytes = Encoding.UTF8.GetBytes(input ?? string.Empty);
            byte[] encrypted = Transform_ctr(source_bytes, key, iv);

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
            byte[] decrypted = Transform_ctr(ciphertext, key, iv);
            return Encoding.UTF8.GetString(decrypted);
        }

        static byte[] Derive_key(string? key_material)
        {
            string material = key_material ?? string.Empty;
            if (material.Length == 0)
                throw new CryptographicException("Для Кузнечика требуется ключевой материал.");

            return SHA256.HashData(Encoding.UTF8.GetBytes(material));
        }

        static byte[] Build_iv(Cipher_options options)
        {
            if (options.Fixed_message_nonce is null)
                return RandomNumberGenerator.GetBytes(Iv_bytes);

            if (options.Fixed_message_nonce.Length == Iv_bytes)
            {
                byte[] iv = new byte[Iv_bytes];
                Array.Copy(options.Fixed_message_nonce, iv, iv.Length);
                return iv;
            }

            byte[] expanded = SHA256.HashData(options.Fixed_message_nonce);
            byte[] result = new byte[Iv_bytes];
            Array.Copy(expanded, result, result.Length);
            return result;
        }

        static byte[] Transform_ctr(byte[] input, byte[] key, byte[] iv)
        {
            if (input.Length == 0)
                return [];

            using Grasshopper algorithm = Grasshopper.Create();
            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.None;
            algorithm.KeySize = Key_bytes * 8;
            algorithm.BlockSize = Iv_bytes * 8;

            using ICryptoTransform encryptor = algorithm.CreateEncryptor(key, null);

            byte[] output = new byte[input.Length];
            byte[] counter = new byte[Iv_bytes];
            Array.Copy(iv, counter, counter.Length);

            byte[] gamma = new byte[Iv_bytes];
            int offset = 0;
            while (offset < input.Length)
            {
                encryptor.TransformBlock(counter, 0, counter.Length, gamma, 0);

                int block_length = Math.Min(Iv_bytes, input.Length - offset);
                for (int i = 0; i < block_length; i++)
                    output[offset + i] = (byte)(input[offset + i] ^ gamma[i]);

                Increment_counter(counter);
                offset += block_length;
            }

            return output;
        }

        static void Increment_counter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0)
                    return;
            }
        }
    }
}
