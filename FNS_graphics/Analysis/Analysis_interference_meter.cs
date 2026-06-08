using System;
using System.Collections.Generic;

namespace FNS_rebuild
{
    internal readonly struct Interference_measurement
    {
        internal Interference_measurement(
            double recovery_ratio,
            double detected_failure_ratio,
            double undetected_damage_ratio)
        {
            Recovery_ratio = recovery_ratio;
            Detected_failure_ratio = detected_failure_ratio;
            Undetected_damage_ratio = undetected_damage_ratio;
        }

        internal double Recovery_ratio { get; }
        internal double Detected_failure_ratio { get; }
        internal double Undetected_damage_ratio { get; }
    }

    internal static class Analysis_interference_meter
    {
        const int Data_shards = 8;
        const int Parity_shards = 4;
        const string Base64_url_symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        internal static Interference_measurement Measure(
            Strategy_wrapper wrapper,
            Cipher_options options,
            int source_length,
            int tests_per_length)
        {
            int recovered = 0;
            int detected_failure = 0;
            int undetected_damage = 0;

            Transmission_error_protection protection = new();

            for (int i = 0; i < tests_per_length; i++)
            {
                string source = Analysis_random_data.Generate_deterministic_string(
                    source_length,
                    seed: source_length * 65537 + i);
                string ciphertext = wrapper.Encrypt(source, options);
                string payload_json = Analysis_transfer_json_builder.Build_payload_json(ciphertext, options);
                Transmission_packet packet = protection.Protect(payload_json, Data_shards, Parity_shards);
                Transmission_packet damaged_packet = Clone_packet(packet);
                Damage_one_shard_symbol(damaged_packet, i);

                try
                {
                    string recovered_payload_json = protection.Recover(damaged_packet);
                    if (string.Equals(recovered_payload_json, payload_json, StringComparison.Ordinal))
                        recovered++;
                    else
                        undetected_damage++;
                }
                catch
                {
                    detected_failure++;
                }
            }

            double denominator = tests_per_length;
            return new Interference_measurement(
                recovered / denominator,
                detected_failure / denominator,
                undetected_damage / denominator);
        }

        static Transmission_packet Clone_packet(Transmission_packet source)
        {
            return new Transmission_packet
            {
                Data_shards = source.Data_shards,
                Parity_shards = source.Parity_shards,
                Padding_size = source.Padding_size,
                Payload_crc32 = source.Payload_crc32,
                Shards_base64url = new List<string?>(source.Shards_base64url),
                Shard_crc32 = new List<uint>(source.Shard_crc32)
            };
        }

        static void Damage_one_shard_symbol(Transmission_packet packet, int test_index)
        {
            if (packet.Shards_base64url.Count == 0)
                return;

            int shard_index = test_index % packet.Shards_base64url.Count;
            string? shard = packet.Shards_base64url[shard_index];
            if (string.IsNullOrEmpty(shard))
                return;

            char[] symbols = shard.ToCharArray();
            int symbol_index = test_index % symbols.Length;
            symbols[symbol_index] = Mutate_base64_url_symbol(symbols[symbol_index]);
            packet.Shards_base64url[shard_index] = new string(symbols);
        }

        static char Mutate_base64_url_symbol(char value)
        {
            int index = Base64_url_symbols.IndexOf(value);
            if (index < 0)
                return 'A';

            return Base64_url_symbols[(index + 1) % Base64_url_symbols.Length];
        }
    }
}
