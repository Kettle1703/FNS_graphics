using System;

namespace FNS_rebuild
{
    internal static class Analysis_random_data
    {
        internal static string Generate_random_string(int length)
        {
            if (length <= 0 || string.IsNullOrEmpty(Factorial_strategy.alphabet))
                return "";

            string alphabet = Factorial_strategy.alphabet;
            int alphabet_length = alphabet.Length;
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
                result[i] = alphabet[Random.Shared.Next(alphabet_length)];

            return new string(result);
        }

        internal static string Generate_deterministic_string(int length, int seed)
        {
            if (length <= 0)
                return "";

            string alphabet = Factorial_strategy.alphabet;
            int alphabet_length = alphabet.Length;
            Random random = new(seed);
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
                result[i] = alphabet[random.Next(alphabet_length)];

            return new string(result);
        }

        internal static string Mutate_one_symbol(string source, int mutation_index)
        {
            if (string.IsNullOrEmpty(source))
                return source;

            string alphabet = Factorial_strategy.alphabet;
            if (alphabet.Length < 2)
                return source;

            int index = mutation_index % source.Length;
            if (index < 0)
                index += source.Length;

            char old_symbol = source[index];
            int old_pos = alphabet.IndexOf(old_symbol);
            if (old_pos < 0)
                old_pos = 0;

            int new_pos = (old_pos + 1) % alphabet.Length;
            char new_symbol = alphabet[new_pos];

            char[] result = source.ToCharArray();
            result[index] = new_symbol;
            return new string(result);
        }

        internal static byte[] Build_fixed_message_nonce(int source_length, int test_index)
        {
            byte[] nonce = new byte[Round_coefficient_cipher.Message_nonce_bytes];
            int seed = unchecked(source_length * 104729 + test_index * 15485863 + 31);
            Random random = new(seed);
            random.NextBytes(nonce);
            return nonce;
        }
    }
}
