using System;

namespace FNS_rebuild
{
    internal static class Analysis_difference
    {
        internal static double Compute_symbol_difference_ratio(string left, string right)
        {
            int min_len = Math.Min(left.Length, right.Length);
            int max_len = Math.Max(left.Length, right.Length);
            if (max_len == 0)
                return 0.0;

            int differences = 0;
            for (int i = 0; i < min_len; i++)
            {
                if (left[i] != right[i])
                    differences++;
            }

            differences += max_len - min_len;
            return (double)differences / max_len;
        }

        internal static double Compute_cipher_payload_difference_ratio(string left, string right, Cipher_options options)
        {
            if (options.Encryption_core != Encryption_core_kind.Factorial)
                return Compute_symbol_difference_ratio(left, right);

            int service_prefix_length = options.Use_blocks()
                ? 4 + Round_coefficient_cipher.Message_nonce_bytes
                : Round_coefficient_cipher.Message_nonce_bytes;

            if (left.Length <= service_prefix_length || right.Length <= service_prefix_length)
                return Compute_symbol_difference_ratio(left, right);

            return Compute_symbol_difference_ratio(
                left.Substring(service_prefix_length),
                right.Substring(service_prefix_length));
        }
    }
}
