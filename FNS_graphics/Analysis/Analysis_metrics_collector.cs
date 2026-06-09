using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace FNS_rebuild
{
    internal static class Analysis_metrics_collector
    {
        const int Default_analysis_key_length = 64;

        internal static Analysis_report Collect(
            Strategy_wrapper wrapper,
            Cipher_options options,
            Performance_report_options report_options,
            Action<string>? write_progress)
        {
            Analysis_report report = new()
            {
                Include_avalanche_sheets = report_options.Include_avalanche_sheet,
                Include_interference_sheet = report_options.Include_interference_sheet
            };

            int total_lengths = ((report_options.Max_length - report_options.Min_length) / report_options.Length_step) + 1;
            int processed = 0;

            for (int length = report_options.Min_length;
                 length <= report_options.Max_length;
                 length += report_options.Length_step)
            {
                Performance_point point = Measure_one_length(
                    wrapper,
                    options,
                    length,
                    report_options,
                    report.Symbol_counts,
                    ref report.Total_ciphertext_symbols);

                report.Points.Add(point);
                processed++;

                if (processed % report_options.Progress_step == 0 || processed == total_lengths)
                    write_progress?.Invoke($"Прогресс анализа: {processed}/{total_lengths} длин");
            }

            return report;
        }

        static Performance_point Measure_one_length(
            Strategy_wrapper wrapper,
            Cipher_options options,
            int length,
            Performance_report_options report_options,
            Dictionary<char, long> symbol_counts,
            ref long total_ciphertext_symbols)
        {
            Basic_measurement basic = Measure_basic_round_trips(
                wrapper,
                options,
                length,
                report_options.Tests_per_length,
                symbol_counts,
                ref total_ciphertext_symbols);

            Pairwise_measurement pairwise = report_options.Include_avalanche_sheet
                ? Measure_pairwise_effects(wrapper, options, length, report_options.Avalanche_tests_per_length)
                : Pairwise_measurement.Empty;

            Interference_measurement interference = report_options.Include_interference_sheet
                ? Analysis_interference_meter.Measure(wrapper, options, length, report_options.Interference_tests_per_length)
                : new Interference_measurement(0, 0, 0);

            return new Performance_point
            {
                Source_length_symbols = length,
                Average_source_bytes = basic.Average_source_bytes,
                Average_ciphertext_bytes = basic.Average_ciphertext_bytes,
                Expansion_ratio = basic.Expansion_ratio,
                Absolute_growth_bytes = basic.Absolute_growth_bytes,
                Average_encrypt_ms = basic.Average_encrypt_ms,
                Average_decrypt_ms = basic.Average_decrypt_ms,
                Encrypt_throughput_bytes_per_second = basic.Encrypt_throughput_bytes_per_second,
                Decrypt_throughput_bytes_per_second = basic.Decrypt_throughput_bytes_per_second,
                Message_avalanche_ratio = pairwise.Message_avalanche_ratio,
                Key_sensitivity_ratio = pairwise.Key_sensitivity_ratio,
                Interference_recovery_ratio = interference.Recovery_ratio,
                Interference_detected_failure_ratio = interference.Detected_failure_ratio,
                Interference_undetected_damage_ratio = interference.Undetected_damage_ratio,
                Interference_safe_outcome_ratio = interference.Recovery_ratio + interference.Detected_failure_ratio
            };
        }

        static Basic_measurement Measure_basic_round_trips(
            Strategy_wrapper wrapper,
            Cipher_options options,
            int length,
            int tests_per_length,
            Dictionary<char, long> symbol_counts,
            ref long total_ciphertext_symbols)
        {
            long total_encrypt_ticks = 0;
            long total_decrypt_ticks = 0;
            long total_source_bytes = 0;
            long total_ciphertext_bytes = 0;

            for (int i = 0; i < tests_per_length; i++)
            {
                string source = Analysis_random_data.Generate_deterministic_string(
                    length,
                    seed: Build_source_seed(length, i));

                Stopwatch encrypt_watch = Stopwatch.StartNew();
                string ciphertext = wrapper.Encrypt(source, options);
                encrypt_watch.Stop();

                Stopwatch decrypt_watch = Stopwatch.StartNew();
                string restored = wrapper.Decrypt(ciphertext, options);
                decrypt_watch.Stop();

                if (restored != source)
                    throw new InvalidOperationException($"Ошибка анализа: decrypt(encrypt(source)) != source для длины {length}.");

                total_encrypt_ticks += encrypt_watch.ElapsedTicks;
                total_decrypt_ticks += decrypt_watch.ElapsedTicks;
                total_source_bytes += Encoding.UTF8.GetByteCount(source);
                total_ciphertext_bytes += Encoding.UTF8.GetByteCount(ciphertext);
                Count_symbols(ciphertext, symbol_counts, ref total_ciphertext_symbols);
            }

            double avg_source_bytes = (double)total_source_bytes / tests_per_length;
            double avg_ciphertext_bytes = (double)total_ciphertext_bytes / tests_per_length;
            double avg_encrypt_ticks = (double)total_encrypt_ticks / tests_per_length;
            double avg_decrypt_ticks = (double)total_decrypt_ticks / tests_per_length;
            double ticks_to_ms = 1000.0 / Stopwatch.Frequency;

            return new Basic_measurement(
                avg_source_bytes,
                avg_ciphertext_bytes,
                avg_source_bytes > 0.0 ? avg_ciphertext_bytes / avg_source_bytes : 0.0,
                avg_ciphertext_bytes - avg_source_bytes,
                avg_encrypt_ticks * ticks_to_ms,
                avg_decrypt_ticks * ticks_to_ms,
                Calculate_throughput(avg_source_bytes, avg_encrypt_ticks),
                Calculate_throughput(avg_source_bytes, avg_decrypt_ticks));
        }

        static Pairwise_measurement Measure_pairwise_effects(
            Strategy_wrapper wrapper,
            Cipher_options options,
            int length,
            int tests_per_length)
        {
            double message_avalanche_sum = 0.0;
            double key_sensitivity_sum = 0.0;
            string base_key = Build_base_key_for_pairwise_tests(options, length);

            for (int i = 0; i < tests_per_length; i++)
            {
                string source = Analysis_random_data.Generate_deterministic_string(length, seed: i + length * 10007);
                string mutated_source = Analysis_random_data.Mutate_one_symbol(source, mutation_index: i);
                byte[] fixed_nonce = Analysis_random_data.Build_fixed_message_nonce(length, i);
                Cipher_options base_key_options = Clone_options_with_key_and_nonce(options, base_key, fixed_nonce);

                string c1 = wrapper.Encrypt(source, base_key_options);
                string c2 = wrapper.Encrypt(mutated_source, base_key_options);
                message_avalanche_sum += Analysis_difference.Compute_cipher_payload_difference_ratio(c1, c2, base_key_options);

                string mutated_key = Analysis_random_data.Mutate_one_symbol(base_key, mutation_index: i);
                Cipher_options mutated_key_options = Clone_options_with_key_and_nonce(options, mutated_key, fixed_nonce);

                c1 = wrapper.Encrypt(source, base_key_options);
                c2 = wrapper.Encrypt(source, mutated_key_options);
                key_sensitivity_sum += Analysis_difference.Compute_cipher_payload_difference_ratio(c1, c2, base_key_options);
            }

            return new Pairwise_measurement(
                message_avalanche_sum / tests_per_length,
                key_sensitivity_sum / tests_per_length);
        }

        static int Build_source_seed(int length, int test_index)
        {
            return unchecked(length * 1000003 + test_index * 9176 + 0x5F3759DF);
        }

        static string Build_base_key_for_pairwise_tests(Cipher_options options, int source_length)
        {
            if (options.Use_key())
                return options.Key;

            int key_length = Math.Min(Default_analysis_key_length, Math.Max(16, source_length));
            return Analysis_random_data.Generate_deterministic_string(key_length, seed: source_length * 7919 + 17);
        }

        static Cipher_options Clone_options_with_key_and_nonce(Cipher_options source, string key, byte[] fixed_message_nonce)
        {
            return new Cipher_options
            {
                Block_plain_text_length = source.Block_plain_text_length,
                Key = key,
                Enable_round_cipher = source.Enable_round_cipher,
                Encryption_core = source.Encryption_core,
                Fixed_message_nonce = fixed_message_nonce
            };
        }

        static double Calculate_throughput(double source_bytes, double elapsed_ticks)
        {
            if (source_bytes <= 0.0 || elapsed_ticks <= 0.0)
                return 0.0;

            return source_bytes * Stopwatch.Frequency / elapsed_ticks;
        }

        static void Count_symbols(string ciphertext, Dictionary<char, long> symbol_counts, ref long total_ciphertext_symbols)
        {
            for (int i = 0; i < ciphertext.Length; i++)
            {
                char symbol = ciphertext[i];
                symbol_counts.TryGetValue(symbol, out long count);
                symbol_counts[symbol] = count + 1;
                total_ciphertext_symbols++;
            }
        }

        readonly struct Basic_measurement
        {
            internal Basic_measurement(
                double average_source_bytes,
                double average_ciphertext_bytes,
                double expansion_ratio,
                double absolute_growth_bytes,
                double average_encrypt_ms,
                double average_decrypt_ms,
                double encrypt_throughput_bytes_per_second,
                double decrypt_throughput_bytes_per_second)
            {
                Average_source_bytes = average_source_bytes;
                Average_ciphertext_bytes = average_ciphertext_bytes;
                Expansion_ratio = expansion_ratio;
                Absolute_growth_bytes = absolute_growth_bytes;
                Average_encrypt_ms = average_encrypt_ms;
                Average_decrypt_ms = average_decrypt_ms;
                Encrypt_throughput_bytes_per_second = encrypt_throughput_bytes_per_second;
                Decrypt_throughput_bytes_per_second = decrypt_throughput_bytes_per_second;
            }

            internal double Average_source_bytes { get; }
            internal double Average_ciphertext_bytes { get; }
            internal double Expansion_ratio { get; }
            internal double Absolute_growth_bytes { get; }
            internal double Average_encrypt_ms { get; }
            internal double Average_decrypt_ms { get; }
            internal double Encrypt_throughput_bytes_per_second { get; }
            internal double Decrypt_throughput_bytes_per_second { get; }
        }

        readonly struct Pairwise_measurement
        {
            internal static Pairwise_measurement Empty => new(0, 0);

            internal Pairwise_measurement(double message_avalanche_ratio, double key_sensitivity_ratio)
            {
                Message_avalanche_ratio = message_avalanche_ratio;
                Key_sensitivity_ratio = key_sensitivity_ratio;
            }

            internal double Message_avalanche_ratio { get; }
            internal double Key_sensitivity_ratio { get; }
        }
    }
}
