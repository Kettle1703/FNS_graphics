using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Digit = System.UInt16;

namespace FNS_rebuild
{
    internal static class Round_coefficient_cipher
    {
        // Новый слой раундового шифрования сериализованных коэффициентов.
        // Работает по байтам (mod 256), поэтому требует алфавит мощности 256.

        internal const int Message_nonce_bytes = 8;
        const int Round_count = 8;
        const int Byte_modulus = 256;

        const string Round_key_stream_label = "FNS_ROUND_KEY_STREAM_V1";
        const string Round_permutation_stream_label = "FNS_ROUND_PERM_STREAM_V1";
        const string Sbox_key_label = "FNS_ROUND_SBOX_KEY_V1";
        const string Sbox_stream_label = "FNS_ROUND_SBOX_STREAM_V1";

        static readonly Dictionary<string, byte[]> key_to_bytes = [];
        static readonly object key_cache_sync = new();
        static readonly byte[] s_box = Build_s_box();
        static readonly byte[] inverse_s_box = Build_inverse_s_box(s_box);

        internal static void Clear_key_cache()
        {
            // Очищает кэш преобразованных ключей при пересборке алфавита.
            lock (key_cache_sync)
                key_to_bytes.Clear();
        }

        internal static byte[] Create_message_nonce()
        {
            // Уникальный nonce на одно сообщение.
            return RandomNumberGenerator.GetBytes(Message_nonce_bytes);
        }

        internal static string Encrypt_block(
            string serialized_coefficients,
            Cipher_options options,
            byte[] message_nonce,
            int block_index)
        {
            return Transform_block(serialized_coefficients, options, message_nonce, block_index, is_encrypt: true);
        }

        internal static string Decrypt_block(
            string serialized_coefficients,
            Cipher_options options,
            byte[] message_nonce,
            int block_index)
        {
            return Transform_block(serialized_coefficients, options, message_nonce, block_index, is_encrypt: false);
        }

        static string Transform_block(
            string serialized_coefficients,
            Cipher_options options,
            byte[] message_nonce,
            int block_index,
            bool is_encrypt)
        {
            if (serialized_coefficients.Length == 0)
                return serialized_coefficients;

            if (!options.Use_key())
                return serialized_coefficients;

            Ensure_byte_alphabet();

            if (message_nonce is null || message_nonce.Length != Message_nonce_bytes)
                throw new InvalidOperationException($"Некорректная длина message nonce: {message_nonce?.Length ?? 0}.");

            if (block_index < 0)
                throw new InvalidOperationException($"Некорректный индекс блока: {block_index}.");

            byte[] key_bytes = Get_key_bytes(options.Key);
            if (key_bytes.Length == 0)
                return serialized_coefficients;

            byte[] state = To_state_bytes(serialized_coefficients);

            if (is_encrypt)
            {
                for (int round_index = 0; round_index < Round_count; round_index++)
                    Encrypt_round(state, key_bytes, message_nonce, block_index, round_index);
            }
            else
            {
                for (int round_index = Round_count - 1; round_index >= 0; round_index--)
                    Decrypt_round(state, key_bytes, message_nonce, block_index, round_index);
            }

            return From_state_bytes(state);
        }

        static void Encrypt_round(byte[] state, byte[] key_bytes, byte[] message_nonce, int block_index, int round_index)
        {
            // Раунд:
            // 1) AddRoundKey (mod 256)
            // 2) S-box
            // 3) Перестановка позиций
            // 4) Диффузионное смешивание соседей

            byte[] round_key = Derive_stream(
                key_bytes,
                message_nonce,
                block_index,
                round_index,
                Round_key_stream_label,
                state.Length);

            Add_round_key(state, round_key);
            Apply_s_box(state, s_box);

            int[] permutation = Build_round_permutation(key_bytes, message_nonce, block_index, round_index, state.Length);
            Apply_permutation(state, permutation);

            Diffuse_forward(state);
        }

        static void Decrypt_round(byte[] state, byte[] key_bytes, byte[] message_nonce, int block_index, int round_index)
        {
            // Обратный раунд:
            // 1) Обратная диффузия
            // 2) Обратная перестановка
            // 3) Обратный S-box
            // 4) Вычитание раундового ключа (mod 256)

            Diffuse_backward(state);

            int[] permutation = Build_round_permutation(key_bytes, message_nonce, block_index, round_index, state.Length);
            Apply_inverse_permutation(state, permutation);

            Apply_s_box(state, inverse_s_box);

            byte[] round_key = Derive_stream(
                key_bytes,
                message_nonce,
                block_index,
                round_index,
                Round_key_stream_label,
                state.Length);

            Subtract_round_key(state, round_key);
        }

        static void Ensure_byte_alphabet()
        {
            // Раундовое шифрование реализовано в пространстве байтов.
            if (Factorial_strategy.power != Byte_modulus)
            {
                throw new InvalidOperationException(
                    $"Раундовое шифрование требует мощность алфавита 256, сейчас: {Factorial_strategy.power}.");
            }
        }

        static byte[] To_state_bytes(string serialized_coefficients)
        {
            byte[] state = new byte[serialized_coefficients.Length];
            for (int i = 0; i < serialized_coefficients.Length; i++)
                state[i] = (byte)Factorial_encoding.char_to_number[serialized_coefficients[i]];

            return state;
        }

        static string From_state_bytes(byte[] state)
        {
            char[] result = new char[state.Length];
            for (int i = 0; i < state.Length; i++)
                result[i] = Factorial_decoding.number_to_char[(Digit)state[i]];

            return new string(result);
        }

        static void Add_round_key(byte[] state, byte[] round_key)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = unchecked((byte)(state[i] + round_key[i]));
        }

        static void Subtract_round_key(byte[] state, byte[] round_key)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = unchecked((byte)(state[i] - round_key[i]));
        }

        static void Apply_s_box(byte[] state, byte[] box)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = box[state[i]];
        }

        static void Apply_permutation(byte[] state, int[] permutation)
        {
            if (state.Length <= 1)
                return;

            byte[] copy = new byte[state.Length];
            Array.Copy(state, copy, state.Length);
            for (int source_index = 0; source_index < state.Length; source_index++)
            {
                int target_index = permutation[source_index];
                state[target_index] = copy[source_index];
            }
        }

        static void Apply_inverse_permutation(byte[] state, int[] permutation)
        {
            if (state.Length <= 1)
                return;

            byte[] copy = new byte[state.Length];
            Array.Copy(state, copy, state.Length);
            for (int source_index = 0; source_index < state.Length; source_index++)
            {
                int target_index = permutation[source_index];
                state[source_index] = copy[target_index];
            }
        }

        static void Diffuse_forward(byte[] state)
        {
            // Треугольное смешивание: каждый байт (кроме первого) накапливает соседа слева.
            // Операция обратима при проходе справа налево с вычитанием.
            for (int i = 1; i < state.Length; i++)
                state[i] = unchecked((byte)(state[i] + state[i - 1]));
        }

        static void Diffuse_backward(byte[] state)
        {
            for (int i = state.Length - 1; i >= 1; i--)
                state[i] = unchecked((byte)(state[i] - state[i - 1]));
        }

        static byte[] Get_key_bytes(string key)
        {
            if (string.IsNullOrEmpty(key))
                return [];

            lock (key_cache_sync)
            {
                if (key_to_bytes.TryGetValue(key, out byte[]? cached) && cached is not null)
                    return cached;

                byte[] result = new byte[key.Length];
                for (int i = 0; i < key.Length; i++)
                    result[i] = (byte)Factorial_encoding.char_to_number[key[i]];

                key_to_bytes[key] = result;
                return result;
            }
        }

        static int[] Build_round_permutation(byte[] key_bytes, byte[] message_nonce, int block_index, int round_index, int length)
        {
            int[] permutation = new int[length];
            for (int i = 0; i < length; i++)
                permutation[i] = i;

            if (length <= 1)
                return permutation;

            Deterministic_stream stream = new(
                key_bytes,
                message_nonce,
                block_index,
                round_index,
                Round_permutation_stream_label);

            for (int i = length - 1; i > 0; i--)
            {
                int j = stream.Next_index(i + 1);
                (permutation[i], permutation[j]) = (permutation[j], permutation[i]);
            }

            return permutation;
        }

        static byte[] Derive_stream(
            byte[] key_bytes,
            byte[] message_nonce,
            int block_index,
            int round_index,
            string label,
            int output_length)
        {
            if (output_length <= 0)
                return [];

            byte[] output = new byte[output_length];
            int offset = 0;
            uint counter = 0;

            using HMACSHA256 hmac = new(key_bytes);
            while (offset < output_length)
            {
                byte[] message = Build_prf_message(label, message_nonce, block_index, round_index, counter);
                byte[] hash = hmac.ComputeHash(message);
                int to_copy = Math.Min(hash.Length, output_length - offset);
                Array.Copy(hash, 0, output, offset, to_copy);
                offset += to_copy;
                counter++;
            }

            return output;
        }

        static byte[] Build_prf_message(string label, byte[] message_nonce, int block_index, int round_index, uint counter)
        {
            byte[] label_bytes = Encoding.UTF8.GetBytes(label);
            byte[] message = new byte[label_bytes.Length + 1 + message_nonce.Length + 4 + 4 + 4];
            int index = 0;

            Array.Copy(label_bytes, 0, message, index, label_bytes.Length);
            index += label_bytes.Length;

            message[index] = (byte)message_nonce.Length;
            index++;

            Array.Copy(message_nonce, 0, message, index, message_nonce.Length);
            index += message_nonce.Length;

            Write_i32(message, ref index, block_index);
            Write_i32(message, ref index, round_index);
            Write_u32(message, ref index, counter);

            return message;
        }

        static void Write_i32(byte[] target, ref int index, int value)
        {
            target[index] = (byte)value;
            target[index + 1] = (byte)(value >> 8);
            target[index + 2] = (byte)(value >> 16);
            target[index + 3] = (byte)(value >> 24);
            index += 4;
        }

        static void Write_u32(byte[] target, ref int index, uint value)
        {
            target[index] = (byte)value;
            target[index + 1] = (byte)(value >> 8);
            target[index + 2] = (byte)(value >> 16);
            target[index + 3] = (byte)(value >> 24);
            index += 4;
        }

        static byte[] Build_s_box()
        {
            byte[] values = new byte[Byte_modulus];
            for (int i = 0; i < values.Length; i++)
                values[i] = (byte)i;

            byte[] sbox_key = SHA256.HashData(Encoding.UTF8.GetBytes(Sbox_key_label));
            byte[] empty_nonce = [];
            Deterministic_stream stream = new(sbox_key, empty_nonce, 0, 0, Sbox_stream_label);
            for (int i = values.Length - 1; i > 0; i--)
            {
                int j = stream.Next_index(i + 1);
                (values[i], values[j]) = (values[j], values[i]);
            }

            return values;
        }

        static byte[] Build_inverse_s_box(byte[] forward_box)
        {
            byte[] inverse = new byte[forward_box.Length];
            for (int i = 0; i < forward_box.Length; i++)
                inverse[forward_box[i]] = (byte)i;

            return inverse;
        }

        sealed class Deterministic_stream
        {
            readonly byte[] key_bytes;
            readonly byte[] message_nonce;
            readonly int block_index;
            readonly int round_index;
            readonly string label;

            byte[] pool = [];
            int pool_index;
            uint counter;

            internal Deterministic_stream(
                byte[] key_bytes,
                byte[] message_nonce,
                int block_index,
                int round_index,
                string label)
            {
                this.key_bytes = key_bytes;
                this.message_nonce = message_nonce;
                this.block_index = block_index;
                this.round_index = round_index;
                this.label = label;
            }

            internal int Next_index(int max_exclusive)
            {
                if (max_exclusive <= 1)
                    return 0;

                ulong range = 1UL << 32;
                ulong limit = range - (range % (ulong)max_exclusive);

                while (true)
                {
                    uint value = Next_u32();
                    if ((ulong)value < limit)
                        return (int)(value % (uint)max_exclusive);
                }
            }

            uint Next_u32()
            {
                if (pool_index + 4 > pool.Length)
                {
                    using HMACSHA256 hmac = new(key_bytes);
                    byte[] message = Build_prf_message(label, message_nonce, block_index, round_index, counter);
                    pool = hmac.ComputeHash(message);
                    pool_index = 0;
                    counter++;
                }

                uint value =
                    (uint)(pool[pool_index] |
                    (pool[pool_index + 1] << 8) |
                    (pool[pool_index + 2] << 16) |
                    (pool[pool_index + 3] << 24));

                pool_index += 4;
                return value;
            }
        }
    }
}
