using System;
using System.IO;
using System.Text;
using static System.Console;
using Digit = System.UInt16;

namespace FNS_rebuild
{
    internal class Analysis
    {
        public static bool debug_mode = false;  // вся отладочная информация будет выводиться в консоль
        const int Default_comparison_block_length = 1096;
        const string Fss_analysis_key = "ANALYSIS_FSS_ROUND_KEY_256";
        const string Standard_core_analysis_key = "ANALYSIS_CORE_COMPARISON_KEY_256";

        public static void Run_three_analysis_reports(Strategy_wrapper wrapper)
        {
            // Пакетный режим анализа для последующей сборки графиков в Python:
            // 1) сравнение ФСС по длине открытого блока 512/1096;
            // 2) сравнение ФСС с раундовым шифрованием и без него;
            // 3) сравнение ядер шифрования между собой.
            string output_dir = Path.Combine(AppContext.BaseDirectory, "analysis_reports");
            Directory.CreateDirectory(output_dir);

            Build_fss_block_length_comparison(output_dir);
            Build_fss_round_cipher_comparison(output_dir);
            Build_encryption_core_comparison(output_dir);
        }

        public static void Print(Digit[] input, int width = 5, int per_line = 10)
        {
            StringBuilder output = new();
            int counter = 1;
            bool no_padding = width <= 0;
            for (int i = input.Length - 1; i >= 0; i--)
            {
                string value = input[i].ToString();
                if (no_padding)
                {
                    output.Append(value);
                }
                else if (width <= value.Length)
                {
                    output.Append(value).Append(' ');
                }
                else
                {
                    output.Append(value.PadRight(width));
                }

                if (per_line > 0 && counter % per_line == 0)
                    output.Append('\n');
                counter++;
            }

            output.Append('\n');
            WriteLine(output.ToString());
        }

        public static void Print_factorial_table()
        {
            for (int i = 0; i < Factorial_encoding.factorial_table.Count; i++)
            {
                WriteLine($"{i + 1}! = ");
                Print(Factorial_encoding.factorial_table[i], width: 0, per_line: -1);
            }
        }

        public static string Generate_random_string(int length)
        {
            return Analysis_random_data.Generate_random_string(length);
        }

        public static int Find_max_source_length_without_blocks()
        {
            // Вычисляет гарантированную максимальную длину без подблоков для ЛЮБОЙ строки.
            int max_factorial_coefficient = 1023;
            int factorial_border_index = max_factorial_coefficient + 1; // 1024

            Digit[] factorial_border_value = [1]; // значение 1024! в длинной арифметике
            for (int i = 2; i <= factorial_border_index; i++)
                factorial_border_value = Long_math.Multiply_by_digit(factorial_border_value, (Digit)i, 0);

            int max_safe_length = 0;
            Digit max_digit = (Digit)(Factorial_strategy.power - 1);

            for (int length = 1; ; length++)
            {
                Digit[] max_number_for_length = new Digit[length]; // power^L - 1
                Array.Fill(max_number_for_length, max_digit);

                if (!Long_math.Less_than(max_number_for_length, factorial_border_value))
                    break;

                max_safe_length = length;
            }

            int first_unsafe_length = max_safe_length + 1;
            int low_byte = max_safe_length & 255;
            int high_byte = (max_safe_length >> 8) & 255;

            StringBuilder output = new();
            output.AppendLine("Анализ гарантированной длины без подблоков завершён.");
            output.AppendLine($"Мощность алфавита: {Factorial_strategy.power}");
            output.AppendLine($"Предел полного коэффициента ФСС в формате: {max_factorial_coefficient}");
            output.AppendLine($"Гарантированная максимальная длина для любой строки: {max_safe_length}");
            output.AppendLine($"Первая потенциально небезопасная длина: {first_unsafe_length}");
            output.AppendLine($"Разложение длины на коэффициенты длины: младший={low_byte}, старший={high_byte}");
            output.Append("Формула критерия: power^L - 1 < 1024!");
            WriteLine(output.ToString());

            return max_safe_length;
        }

        public static void Build_performance_report(
            Strategy_wrapper wrapper,
            Cipher_options options,
            Performance_report_options? report_options = null)
        {
            report_options ??= new Performance_report_options();
            report_options.Validate();

            WriteLine("Запуск анализа производительности шифрования...");
            WriteLine($"Диапазон длин: {report_options.Min_length}..{report_options.Max_length}");
            WriteLine($"Повторов Encrypt/Decrypt на длину: {report_options.Tests_per_length}");
            if (report_options.Include_avalanche_sheet)
                WriteLine($"Парных тестов лавины/ключа на длину: {report_options.Avalanche_tests_per_length}");
            if (report_options.Include_interference_sheet)
                WriteLine($"Тестов помехоустойчивости на длину: {report_options.Interference_tests_per_length}");

            Analysis_report report = Analysis_metrics_collector.Collect(
                wrapper,
                options,
                report_options,
                write_progress: WriteLine);

            Analysis_excel_report_writer.Save(report, report_options.Output_xlsx_path);

            WriteLine($"Анализ завершён. Файл создан: {report_options.Output_xlsx_path}");
        }

        static void Build_fss_block_length_comparison(string output_dir)
        {
            Performance_report_options options = Build_default_comparison_options(
                Path.Combine(output_dir, "01_fss_block_length_comparison.xlsx"));

            Analysis_comparison_series[] series =
            [
                Collect_series(
                    "ФСС, блок 512",
                    new Strategy_wrapper(new Factorial_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = 512,
                        Key = Fss_analysis_key,
                        Enable_round_cipher = true,
                        Encryption_core = Encryption_core_kind.Factorial
                    },
                    options),
                Collect_series(
                    "ФСС, блок 1096",
                    new Strategy_wrapper(new Factorial_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = 1096,
                        Key = Fss_analysis_key,
                        Enable_round_cipher = true,
                        Encryption_core = Encryption_core_kind.Factorial
                    },
                    options)
            ];

            Analysis_comparison_excel_writer.Save(series, options.Output_xlsx_path);
            WriteLine($"Сравнение длин блоков ФСС создано: {options.Output_xlsx_path}");
        }

        static void Build_fss_round_cipher_comparison(string output_dir)
        {
            Performance_report_options options = Build_default_comparison_options(
                Path.Combine(output_dir, "02_fss_round_cipher_comparison.xlsx"));

            Analysis_comparison_series[] series =
            [
                Collect_series(
                    "ФСС, раундовое шифрование включено",
                    new Strategy_wrapper(new Factorial_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = Default_comparison_block_length,
                        Key = Fss_analysis_key,
                        Enable_round_cipher = true,
                        Encryption_core = Encryption_core_kind.Factorial
                    },
                    options),
                Collect_series(
                    "ФСС, раундовое шифрование отключено",
                    new Strategy_wrapper(new Factorial_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = Default_comparison_block_length,
                        Key = Fss_analysis_key,
                        Enable_round_cipher = false,
                        Encryption_core = Encryption_core_kind.Factorial
                    },
                    options)
            ];

            Analysis_comparison_excel_writer.Save(series, options.Output_xlsx_path);
            WriteLine($"Сравнение раундового слоя ФСС создано: {options.Output_xlsx_path}");
        }

        static void Build_encryption_core_comparison(string output_dir)
        {
            Performance_report_options options = Build_default_comparison_options(
                Path.Combine(output_dir, "03_encryption_core_comparison.xlsx"));

            Analysis_comparison_series[] series =
            [
                Collect_series(
                    Encryption_core_catalog.Factorial_display_name,
                    new Strategy_wrapper(new Factorial_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = Default_comparison_block_length,
                        Key = Fss_analysis_key,
                        Enable_round_cipher = true,
                        Encryption_core = Encryption_core_kind.Factorial
                    },
                    options),
                Collect_series(
                    Encryption_core_catalog.Aes_gcm_display_name,
                    new Strategy_wrapper(new Aes_gcm_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = 0,
                        Key = Standard_core_analysis_key,
                        Enable_round_cipher = false,
                        Encryption_core = Encryption_core_kind.AesGcm
                    },
                    options),
                Collect_series(
                    Encryption_core_catalog.Kuznyechik_ctr_display_name,
                    new Strategy_wrapper(new Kuznyechik_strategy()),
                    new Cipher_options
                    {
                        Block_plain_text_length = 0,
                        Key = Standard_core_analysis_key,
                        Enable_round_cipher = false,
                        Encryption_core = Encryption_core_kind.KuznyechikCtr
                    },
                    options)
            ];

            Analysis_comparison_excel_writer.Save(series, options.Output_xlsx_path);
            WriteLine($"Сравнение ядер шифрования создано: {options.Output_xlsx_path}");
        }

        static Performance_report_options Build_default_comparison_options(string output_path)
        {
            return new Performance_report_options
            {
                Min_length = 1,
                Max_length = 5000,
                Tests_per_length = 3,
                Avalanche_tests_per_length = 3,
                Interference_tests_per_length = 3,
                Progress_step = 250,
                Output_xlsx_path = output_path,
                Include_avalanche_sheet = true,
                Include_interference_sheet = true
            };
        }

        static Analysis_comparison_series Collect_series(
            string name,
            Strategy_wrapper wrapper,
            Cipher_options cipher_options,
            Performance_report_options report_options)
        {
            WriteLine($"Сбор серии: {name}");
            Analysis_report report = Analysis_metrics_collector.Collect(
                wrapper,
                cipher_options,
                report_options,
                write_progress: message => WriteLine($"{name}: {message}"));

            return new Analysis_comparison_series(name, report);
        }
    }
}
