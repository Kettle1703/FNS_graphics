using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
using OfficeOpenXml;
using System.Diagnostics;
using System.Text;

namespace FNS_rebuild
{
    internal class Analysis
    {
        public static bool debug_mode = false;  // вся отладочная информация будет выводиться в консоль 
        const int Default_analysis_key_length = 64;  // длина служебного ключа для теста чувствительности к ключу

        public static void Run_three_analysis_reports(Strategy_wrapper wrapper)
        {
            // Пакетный режим анализа:
            // 1) типичный блок 512, длины 1..5000;
            // 2) рабочий блок 1096, длины 1..5000;
            // 3) одноблочный профиль 1096, длины 1..1096.
            // Каждый прогон пишет отдельный xlsx-файл.
            string output_dir = Path.Combine(AppContext.BaseDirectory, "analysis_reports");
            Directory.CreateDirectory(output_dir);

            Build_performance_report(
                wrapper,
                new Cipher_options { Block_plain_text_length = 512, Key = "" },
                new Performance_report_options
                {
                    Min_length = 1,
                    Max_length = 5000,
                    Tests_per_length = 3,
                    Avalanche_tests_per_length = 3,
                    Progress_step = 250,
                    Output_xlsx_path = Path.Combine(output_dir, "analysis_block_512_len_1_5000.xlsx"),
                    Include_avalanche_sheet = true
                });

            Build_performance_report(
                wrapper,
                new Cipher_options { Block_plain_text_length = 1096, Key = "" },
                new Performance_report_options
                {
                    Min_length = 1,
                    Max_length = 5000,
                    Tests_per_length = 3,
                    Avalanche_tests_per_length = 3,
                    Progress_step = 250,
                    Output_xlsx_path = Path.Combine(output_dir, "analysis_block_1096_len_1_5000.xlsx"),
                    Include_avalanche_sheet = true
                });

            Build_performance_report(
                wrapper,
                new Cipher_options { Block_plain_text_length = 1096, Key = "" },
                new Performance_report_options
                {
                    Min_length = 1,
                    Max_length = 1096,
                    Tests_per_length = 3,
                    Avalanche_tests_per_length = 3,
                    Progress_step = 100,
                    Output_xlsx_path = Path.Combine(output_dir, "analysis_singleblock_1096_len_1_1096.xlsx"),
                    Include_avalanche_sheet = true
                });
        }

        internal sealed class Performance_report_options
        {
            // Диапазон длин исходной строки (ось X).
            public int Min_length = 1;
            public int Max_length = 5000;

            // Количество прогонов Encrypt/Decrypt для каждой длины (усреднение).
            public int Tests_per_length = 3;

            // Количество прогонов лавинного теста для каждой длины (усреднение).
            public int Avalanche_tests_per_length = 3;

            // Шаг вывода прогресса в консоль.
            public int Progress_step = 250;

            // Путь до одного итогового xlsx-файла.
            public string Output_xlsx_path = Path.Combine(AppContext.BaseDirectory, "FNS_analysis.xlsx");

            // Включать ли лист лавинного теста.
            public bool Include_avalanche_sheet = true;
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
            output.Append("\n");
            WriteLine(output.ToString());
        }

        public static void Print_factorial_table()
        {
            // выводит заполненную таблицу факториалов из Factorial_encoding.factorial_table
            for (int i = 0; i < Factorial_encoding.factorial_table.Count; i++)
            {
                WriteLine($"{i + 1}! = ");
                Print(Factorial_encoding.factorial_table[i], width: 0, per_line: -1);
            }
        }

        public static string Generate_random_string(int length)
        {
            // генерирует случайную строку заданной длины из символов Factorial_strategy.alphabet
            if (length <= 0 || string.IsNullOrEmpty(Factorial_strategy.alphabet))
                return "";

            string alphabet = Factorial_strategy.alphabet;
            int alphabet_length = alphabet.Length;
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
                result[i] = alphabet[Random.Shared.Next(alphabet_length)];

            return new string(result);
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
            // Строит один xlsx-документ с листами данных:
            // 1) коэффициент увеличения;
            // 2) абсолютный прирост длины;
            // 3) скорость Encrypt;
            // 4) скорость Decrypt;
            // 5) распределение символов;
            // 6) лавинный эффект (опционально).

            report_options ??= new Performance_report_options();
            Validate_report_options(report_options);

            List<Performance_point> points = [];
            Dictionary<char, long> symbol_counts = [];
            long total_ciphertext_symbols = 0;

            int total_lengths = (report_options.Max_length - report_options.Min_length) + 1;
            int processed = 0;

            WriteLine("Запуск анализа производительности шифрования...");
            WriteLine($"Диапазон длин: {report_options.Min_length}..{report_options.Max_length}");
            WriteLine($"Повторов на длину: {report_options.Tests_per_length}");
            if (report_options.Include_avalanche_sheet)
                WriteLine($"Повторов лавинного теста на длину: {report_options.Avalanche_tests_per_length}");

            for (int length = report_options.Min_length; length <= report_options.Max_length; length++)
            {
                Performance_point point = Measure_one_length(
                    wrapper,
                    options,
                    length,
                    report_options.Tests_per_length,
                    report_options.Avalanche_tests_per_length,
                    report_options.Include_avalanche_sheet,
                    symbol_counts,
                    ref total_ciphertext_symbols);

                points.Add(point);
                processed++;

                if (processed % report_options.Progress_step == 0 || processed == total_lengths)
                    WriteLine($"Прогресс анализа: {processed}/{total_lengths} длин");
            }

            Save_report_to_excel(
                points,
                report_options.Output_xlsx_path,
                symbol_counts,
                total_ciphertext_symbols,
                report_options.Include_avalanche_sheet);

            WriteLine($"Анализ завершён. Файл создан: {report_options.Output_xlsx_path}");
        }

        static void Validate_report_options(Performance_report_options options)
        {
            if (options.Min_length < 1)
                throw new ArgumentOutOfRangeException(nameof(options.Min_length), "Минимальная длина должна быть >= 1.");

            if (options.Max_length < options.Min_length)
                throw new ArgumentOutOfRangeException(nameof(options.Max_length), "Максимальная длина должна быть >= минимальной.");

            if (options.Tests_per_length < 1)
                throw new ArgumentOutOfRangeException(nameof(options.Tests_per_length), "Тестов на длину должно быть >= 1.");

            if (options.Avalanche_tests_per_length < 1)
                throw new ArgumentOutOfRangeException(nameof(options.Avalanche_tests_per_length), "Лавинных тестов на длину должно быть >= 1.");

            if (options.Progress_step < 1)
                throw new ArgumentOutOfRangeException(nameof(options.Progress_step), "Шаг прогресса должен быть >= 1.");

            if (string.IsNullOrWhiteSpace(options.Output_xlsx_path))
                throw new ArgumentException("Нужно указать путь для выходного xlsx-файла.", nameof(options.Output_xlsx_path));
        }

        static Performance_point Measure_one_length(
            Strategy_wrapper wrapper,
            Cipher_options options,
            int length,
            int tests_per_length,
            int avalanche_tests_per_length,
            bool include_avalanche,
            Dictionary<char, long> symbol_counts,
            ref long total_ciphertext_symbols)
        {
            long total_encrypt_ticks = 0;
            long total_decrypt_ticks = 0;
            long total_ciphertext_length = 0;
            double avalanche_sum = 0.0;

            for (int i = 0; i < tests_per_length; i++)
            {
                string source = Generate_random_string(length);

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
                total_ciphertext_length += ciphertext.Length;
                Count_symbols(ciphertext, symbol_counts, ref total_ciphertext_symbols);
            }

            if (include_avalanche)
            {
                string base_key = Build_base_key_for_avalanche(options, length);
                Cipher_options base_key_options = Clone_options_with_key(options, base_key);

                for (int i = 0; i < avalanche_tests_per_length; i++)
                {
                    // Для оценки чувствительности к ключу фиксируется открытый текст,
                    // меняется только один символ симметрического ключа.
                    string source = Generate_deterministic_string(length, seed: i + length * 10007);
                    string mutated_key = Mutate_one_symbol(base_key, mutation_index: i);
                    Cipher_options mutated_key_options = Clone_options_with_key(options, mutated_key);

                    string c1 = wrapper.Encrypt(source, base_key_options);
                    string c2 = wrapper.Encrypt(source, mutated_key_options);
                    avalanche_sum += Compute_symbol_difference_ratio(c1, c2);
                }
            }

            double ticks_to_ms = 1000.0 / Stopwatch.Frequency;
            double avg_encrypt_ms = (total_encrypt_ticks * ticks_to_ms) / tests_per_length;
            double avg_decrypt_ms = (total_decrypt_ticks * ticks_to_ms) / tests_per_length;
            double avg_ciphertext_length = (double)total_ciphertext_length / tests_per_length;
            double expansion_ratio = avg_ciphertext_length / length;
            double absolute_growth = avg_ciphertext_length - length;
            double avalanche_ratio = include_avalanche
                ? avalanche_sum / avalanche_tests_per_length
                : 0.0;

            return new Performance_point
            {
                Source_length = length,
                Average_ciphertext_length = avg_ciphertext_length,
                Expansion_ratio = expansion_ratio,
                Absolute_growth = absolute_growth,
                Average_encrypt_ms = avg_encrypt_ms,
                Average_decrypt_ms = avg_decrypt_ms,
                Avalanche_difference_ratio = avalanche_ratio
            };
        }

        static string Generate_deterministic_string(int length, int seed)
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

        static string Mutate_one_symbol(string source, int mutation_index)
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

        static string Build_base_key_for_avalanche(Cipher_options options, int source_length)
        {
            // Возвращает базовый ключ для теста чувствительности к ключу.
            if (options.Use_key())
                return options.Key;

            int key_length = Math.Min(Default_analysis_key_length, Math.Max(16, source_length));
            return Generate_deterministic_string(key_length, seed: source_length * 7919 + 17);
        }

        static Cipher_options Clone_options_with_key(Cipher_options source, string key)
        {
            // Создаёт копию настроек с заменой только ключа.
            return new Cipher_options
            {
                Block_plain_text_length = source.Block_plain_text_length,
                Key = key
            };
        }

        static double Compute_symbol_difference_ratio(string left, string right)
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

        static void Save_report_to_excel(
            List<Performance_point> points,
            string output_xlsx_path,
            Dictionary<char, long> symbol_counts,
            long total_ciphertext_symbols,
            bool include_avalanche_sheet)
        {
            string? directory = Path.GetDirectoryName(output_xlsx_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            FileInfo file = new(output_xlsx_path);
            if (file.Exists)
                file.Delete();

            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

            using ExcelPackage package = new(file);

            ExcelWorksheet expansion_sheet = package.Workbook.Worksheets.Add("Коэф_увеличения");
            Fill_expansion_sheet(expansion_sheet, points);

            ExcelWorksheet absolute_growth_sheet = package.Workbook.Worksheets.Add("Абс_прирост");
            Fill_absolute_growth_sheet(absolute_growth_sheet, points);

            ExcelWorksheet encrypt_sheet = package.Workbook.Worksheets.Add("Скорость_Encrypt");
            Fill_speed_sheet(encrypt_sheet, points, is_encrypt: true);

            ExcelWorksheet decrypt_sheet = package.Workbook.Worksheets.Add("Скорость_Decrypt");
            Fill_speed_sheet(decrypt_sheet, points, is_encrypt: false);

            ExcelWorksheet distribution_sheet = package.Workbook.Worksheets.Add("Распределение");
            Fill_distribution_sheet(distribution_sheet, symbol_counts, total_ciphertext_symbols);

            if (include_avalanche_sheet)
            {
                ExcelWorksheet avalanche_sheet = package.Workbook.Worksheets.Add("Лавинный_эффект");
                Fill_avalanche_sheet(avalanche_sheet, points);
            }

            package.Save();
        }

        static void Fill_expansion_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки";
            sheet.Cells[1, 2].Value = "Средняя длина шифротекста";
            sheet.Cells[1, 3].Value = "Коэффициент увеличения";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length;
                sheet.Cells[row, 2].Value = point.Average_ciphertext_length;
                sheet.Cells[row, 3].Value = point.Expansion_ratio;
                row++;
            }

            sheet.Cells[2, 2, row - 1, 2].Style.Numberformat.Format = "0.000";
            sheet.Cells[2, 3, row - 1, 3].Style.Numberformat.Format = "0.000000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_absolute_growth_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки";
            sheet.Cells[1, 2].Value = "Абсолютный прирост |C|-|M|";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length;
                sheet.Cells[row, 2].Value = point.Absolute_growth;
                row++;
            }

            sheet.Cells[2, 2, row - 1, 2].Style.Numberformat.Format = "0.000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_speed_sheet(ExcelWorksheet sheet, List<Performance_point> points, bool is_encrypt)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки";
            sheet.Cells[1, 2].Value = is_encrypt ? "Среднее время шифрования, мс" : "Среднее время дешифрования, мс";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length;
                sheet.Cells[row, 2].Value = is_encrypt ? point.Average_encrypt_ms : point.Average_decrypt_ms;
                row++;
            }

            sheet.Cells[2, 2, row - 1, 2].Style.Numberformat.Format = "0.000000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_distribution_sheet(
            ExcelWorksheet sheet,
            Dictionary<char, long> symbol_counts,
            long total_ciphertext_symbols)
        {
            sheet.Cells[1, 1].Value = "Индекс символа";
            sheet.Cells[1, 2].Value = "Символ";
            sheet.Cells[1, 3].Value = "Количество";
            sheet.Cells[1, 4].Value = "Доля";

            int row = 2;
            string alphabet = Factorial_strategy.alphabet;

            for (int i = 0; i < alphabet.Length; i++)
            {
                char symbol = alphabet[i];
                symbol_counts.TryGetValue(symbol, out long count);
                double share = total_ciphertext_symbols > 0
                    ? (double)count / total_ciphertext_symbols
                    : 0.0;

                sheet.Cells[row, 1].Value = i;
                sheet.Cells[row, 2].Value = symbol.ToString();
                sheet.Cells[row, 3].Value = count;
                sheet.Cells[row, 4].Value = share;
                row++;
            }

            double entropy = Compute_entropy(symbol_counts, total_ciphertext_symbols);
            sheet.Cells[1, 6].Value = "Всего символов";
            sheet.Cells[1, 7].Value = total_ciphertext_symbols;
            sheet.Cells[2, 6].Value = "Энтропия (бит/символ)";
            sheet.Cells[2, 7].Value = entropy;

            sheet.Cells[2, 4, row - 1, 4].Style.Numberformat.Format = "0.000000";
            sheet.Cells[2, 7].Style.Numberformat.Format = "0.000000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_avalanche_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            // Лавинный эффект по ключу: доля отличающихся символов двух шифротекстов
            // при фиксированном открытом тексте и изменении одного символа ключа.
            sheet.Cells[1, 1].Value = "Длина исходной строки";
            sheet.Cells[1, 2].Value = "Средняя доля отличий шифротекстов (изменение 1 символа ключа)";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length;
                sheet.Cells[row, 2].Value = point.Avalanche_difference_ratio;
                row++;
            }

            sheet.Cells[2, 2, row - 1, 2].Style.Numberformat.Format = "0.000000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static double Compute_entropy(Dictionary<char, long> symbol_counts, long total_ciphertext_symbols)
        {
            if (total_ciphertext_symbols <= 0)
                return 0.0;

            double entropy = 0.0;
            foreach (var pair in symbol_counts)
            {
                if (pair.Value <= 0)
                    continue;

                double p = (double)pair.Value / total_ciphertext_symbols;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }

        sealed class Performance_point
        {
            internal int Source_length = 0;
            internal double Average_ciphertext_length = 0;
            internal double Expansion_ratio = 0;
            internal double Absolute_growth = 0;
            internal double Average_encrypt_ms = 0;
            internal double Average_decrypt_ms = 0;
            internal double Avalanche_difference_ratio = 0;
        }
    }
}
