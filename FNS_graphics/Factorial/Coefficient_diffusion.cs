using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
namespace FNS_rebuild
{
    internal class Coefficient_diffusion
    {
        // Класс отвечает за простое ключевое наложение на сериализованный поток коэффициентов.
        // Наложение выполняется уже после сжатия коэффициентов в диапазон 0..power-1.

        static Dictionary<string, Digit[]> key_to_symbol_codes = [];  // кэш кодов ключа в текущем алфавите

        internal static void Clear_key_cache()
        {
            // Очищает кэш ключей при пересоздании алфавита.

            key_to_symbol_codes.Clear();
        }

        internal static string Encrypt(string serialized_coefficients, Cipher_options options)
        {
            // Шифрование: c'_i = (c_i + k_i) mod power.

            return Apply_key_overlay(serialized_coefficients, options, is_encrypt: true);
        }

        internal static string Decrypt(string serialized_coefficients, Cipher_options options)
        {
            // Дешифрование: c_i = (c'_i - k_i) mod power.

            return Apply_key_overlay(serialized_coefficients, options, is_encrypt: false);
        }

        static string Apply_key_overlay(string serialized_coefficients, Cipher_options options, bool is_encrypt)
        {
            if (serialized_coefficients.Length == 0)
                return serialized_coefficients;

            if (!options.Use_key())
                return serialized_coefficients;

            Digit[] key_codes = Get_key_symbol_codes(options.Key);
            if (key_codes.Length == 0)
                return serialized_coefficients;

            int modulus = Factorial_strategy.power;
            char[] result = new char[serialized_coefficients.Length];

            for (int i = 0; i < serialized_coefficients.Length; i++)
            {
                int source_value = Factorial_encoding.char_to_number[serialized_coefficients[i]];
                int key_value = key_codes[i % key_codes.Length];

                int mixed = is_encrypt
                    ? source_value + key_value
                    : source_value - key_value;

                mixed = Positive_mod(mixed, modulus);
                result[i] = Factorial_decoding.number_to_char[(Digit)mixed];
            }

            return new string(result);
        }

        static Digit[] Get_key_symbol_codes(string key)
        {
            // Ключ переводится в коды символов текущего алфавита.

            if (string.IsNullOrEmpty(key))
                return [];

            if (key_to_symbol_codes.TryGetValue(key, out Digit[]? cached) && cached is not null)
                return cached;

            Digit[] result = new Digit[key.Length];
            for (int i = 0; i < key.Length; i++)
                result[i] = Factorial_encoding.char_to_number[key[i]];

            key_to_symbol_codes[key] = result;
            return result;
        }

        static int Positive_mod(int value, int modulus)
        {
            // Возвращает неотрицательный остаток для обратной формулы с вычитаниями.

            int result = value % modulus;
            if (result < 0)
                result += modulus;

            return result;
        }

    }
}
