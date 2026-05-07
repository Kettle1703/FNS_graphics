using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
namespace FNS_rebuild
{
    internal class Stochastic_tests_encryption
    {
        internal const int Fast_min_length = 1;  // Нижняя граница длины строки для быстрого профиля.
        internal const int Fast_max_length_without_blocks = 1096;  // Верхняя граница длины, где тест идёт без блочного режима.
        internal const int Fast_max_length_with_blocks = 5000;  // Максимальная длина строки в быстром профиле (включая блочный режим).
        internal const int Fast_block_plain_text_length = 1096;  // Длина открытого блока, которая используется в авто-режиме после 1096.
        internal const int Fast_tests_per_length = 1;  // Количество раундов на одну длину; рост этого числа сильно замедляет тест.
        internal const int Fast_progress_step = 500;  // Шаг печати прогресса по длинам; чем меньше шаг, тем медленнее из-за частого вывода в консоль.

        internal static bool Run_fast_profile(Strategy_wrapper wrapper)
        {
            // Быстрый профиль для повседневной проверки шифрования.
            // До длины Fast_max_length_without_blocks тест идёт без блоков.
            // Начиная с Fast_max_length_without_blocks + 1 автоматически включается блочное шифрование.

            return Run_round_trip_tests(
                wrapper,
                min_length: Fast_min_length,
                max_length: Fast_max_length_with_blocks,
                tests_per_length: Fast_tests_per_length,
                progress_step: Fast_progress_step,
                options: null);
        }

        internal static bool Run_round_trip_tests(
            Strategy_wrapper wrapper,
            int min_length,
            int max_length,
            int tests_per_length,
            int progress_step,
            Cipher_options? options = null)
        {
            // Для каждой длины генерирует tests_per_length строк,
            // выполняет Encrypt -> Decrypt и сравнивает с исходной строкой.
            // При первой ошибке сразу завершает тестирование.
            // Если options передан, используются фиксированные настройки.
            // Если options == null, метод сам выбирает режим по длине:
            // длины до Fast_max_length_without_blocks шифруются без блоков,
            // более длинные строки — в блочном режиме.

            int total_lengths = max_length - min_length + 1;
            int total_tests = total_lengths * tests_per_length;
            int passed_tests = 0;

            WriteLine(Build_start_report(min_length, max_length, tests_per_length, total_tests));

            for (int length = min_length; length <= max_length; length++)
            {
                Cipher_options effective_options = options ?? Build_auto_options_for_length(length);

                for (int test_index = 1; test_index <= tests_per_length; test_index++)
                {
                    string source = Analysis.Generate_random_string(length);
                    string encrypted = wrapper.Encrypt(source, effective_options);
                    string decrypted = wrapper.Decrypt(encrypted, effective_options);

                    if (decrypted != source)
                    {
                        int mismatch_index = Find_first_mismatch(source, decrypted);
                        WriteLine(Build_mismatch_report(
                            source,
                            encrypted,
                            decrypted,
                            length,
                            test_index,
                            tests_per_length,
                            mismatch_index));
                        Finish_signal();
                        return false;
                    }

                    passed_tests++;
                }

                int processed_lengths = length - min_length + 1;
                if (processed_lengths % progress_step == 0 || length == max_length)
                    WriteLine(Build_progress_report(length, passed_tests, total_tests));
            }

            WriteLine(Build_success_report(passed_tests, total_tests));
            Finish_signal();
            return true;
        }

        static Cipher_options Build_auto_options_for_length(int length)
        {
            // Возвращает автоматические настройки для быстрого профиля.
            // Для коротких строк шифрование без блоков, для длинных — блочное.

            if (length <= Fast_max_length_without_blocks)
                return Cipher_options.Default;

            return new Cipher_options
            {
                Block_plain_text_length = Fast_block_plain_text_length,
                Key = ""
            };
        }

        static string Build_start_report(int min_length, int max_length, int tests_per_length, int total_tests)
        {
            // Формирует стартовую сводку тестирования.

            System.Text.StringBuilder output = new();
            output.AppendLine("Стохастическое тестирование шифрования запущено.");
            output.AppendLine($"Диапазон длин: {min_length}..{max_length}");
            output.AppendLine($"Тестов на каждую длину: {tests_per_length}");
            output.Append($"Всего раундов шифрование -> дешифрование: {total_tests}");
            return output.ToString();
        }

        static string Build_progress_report(int length, int passed_tests, int total_tests)
        {
            // Формирует сообщение о прогрессе.

            System.Text.StringBuilder output = new();
            output.AppendLine("Прогресс стохастического тестирования:");
            output.AppendLine($"Проверена текущая длина: {length}");
            output.Append($"Успешных раундов: {passed_tests}/{total_tests}");
            return output.ToString();
        }

        static string Build_success_report(int passed_tests, int total_tests)
        {
            // Формирует итоговое сообщение при полном успешном прохождении.

            System.Text.StringBuilder output = new();
            output.AppendLine("Стохастическое тестирование шифрования завершено успешно.");
            output.Append($"Успешных раундов: {passed_tests}/{total_tests}");
            return output.ToString();
        }

        static string Build_mismatch_report(
            string source,
            string encrypted,
            string decrypted,
            int length,
            int test_index,
            int tests_per_length,
            int mismatch_index)
        {
            // Формирует подробный отчёт о первом найденном несовпадении.

            System.Text.StringBuilder output = new();
            output.AppendLine("Стохастическое тестирование завершено с ошибкой.");
            output.AppendLine("Расшифрованная строка не совпадает с исходной.");
            output.AppendLine($"Длина теста: {length}");
            output.AppendLine($"Номер теста на этой длине: {test_index}/{tests_per_length}");
            output.AppendLine($"Длина исходной строки: {source.Length}");
            output.AppendLine($"Длина расшифрованной строки: {decrypted.Length}");
            output.AppendLine($"Длина шифротекста: {encrypted.Length}");
            Append_factorial_diagnostics(output, source);

            if (mismatch_index >= 0)
            {
                int one_based = mismatch_index + 1;
                char source_symbol = mismatch_index < source.Length ? source[mismatch_index] : '\0';
                char decrypted_symbol = mismatch_index < decrypted.Length ? decrypted[mismatch_index] : '\0';
                int source_code = Symbol_to_numeric_code(source_symbol);
                int decrypted_code = Symbol_to_numeric_code(decrypted_symbol);

                output.AppendLine($"Индекс первого отличия (с 0): {mismatch_index}");
                output.AppendLine($"Индекс первого отличия (с 1): {one_based}");
                output.AppendLine($"Исходный символ в точке отличия: '{source_symbol}' (код {source_code})");
                output.AppendLine($"Расшифрованный символ в точке отличия: '{decrypted_symbol}' (код {decrypted_code})");
                output.AppendLine($"Контекст исходной строки: {Build_context(source, mismatch_index, 8)}");
                output.AppendLine($"Контекст расшифрованной строки: {Build_context(decrypted, mismatch_index, 8)}");
            }

            output.AppendLine($"Исходная строка: {source}");
            output.AppendLine($"Шифротекст: {encrypted}");
            output.Append($"Расшифрованная строка: {decrypted}");
            return output.ToString();
        }

        static void Append_factorial_diagnostics(System.Text.StringBuilder output, string source)
        {
            // Добавляет техдиагностику по коэффициентам ФСС для поиска переполнения упаковки.

            Digit[] source_digits = Long_math.To_array(source);
            Digit[] normalized = Trim_high_zeros_local(source_digits);
            Digit[] factorial_coefficients = Factorial_encoding.Convert_to_factorial_system(normalized);

            int max_factorial_coefficient = 0;
            int overflow_count = 0;
            int first_overflow_index = -1;

            for (int i = 0; i < factorial_coefficients.Length; i++)
            {
                int value = factorial_coefficients[i];
                if (value > max_factorial_coefficient)
                    max_factorial_coefficient = value;

                if (value > 1023)
                {
                    overflow_count++;
                    if (first_overflow_index < 0)
                        first_overflow_index = i;
                }
            }

            output.AppendLine($"Максимальный коэффициент ФСС: {max_factorial_coefficient}");
            output.AppendLine($"Количество коэффициентов ФСС > 1023: {overflow_count}");
            if (first_overflow_index >= 0)
                output.AppendLine($"Первый коэффициент ФСС > 1023 (индекс с 0): {first_overflow_index}");
        }

        static Digit[] Trim_high_zeros_local(Digit[] input)
        {
            // Локальная версия удаления старших нулей для диагностики.

            int last = input.Length - 1;
            while (last > 0 && input[last] == 0)
                last--;

            if (last == input.Length - 1)
                return input;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(input, trimmed, trimmed.Length);
            return trimmed;
        }

        static int Find_first_mismatch(string left, string right)
        {
            // Возвращает индекс первого отличающегося символа, -1 если строки равны.

            int min_length = Math.Min(left.Length, right.Length);
            for (int i = 0; i < min_length; i++)
            {
                if (left[i] != right[i])
                    return i;
            }

            if (left.Length == right.Length)
                return -1;

            return min_length;
        }

        static int Symbol_to_numeric_code(char symbol)
        {
            // Возвращает числовой код символа в алфавите шифрования,
            // если символа нет в таблице, возвращает Unicode-код символа.

            if (Factorial_encoding.char_to_number.TryGetValue(symbol, out Digit value))
                return value;

            return symbol;
        }

        static string Build_context(string text, int index, int radius)
        {
            // Формирует короткий фрагмент вокруг индекса для быстрого просмотра ошибки.

            if (text.Length == 0)
                return "<пусто>";

            int start = index - radius;
            if (start < 0)
                start = 0;

            int end = index + radius;
            if (end >= text.Length)
                end = text.Length - 1;

            int length = end - start + 1;
            return text.Substring(start, length);
        }

        static void Finish_signal()
        {
            // Звуковой сигнал о завершении тестирования: три отдельных коротких сигнала.
            // Console.Beep используется вместо '\a', потому что в некоторых терминалах
            // управляющий символ может быть отключён и звучит только один раз.
            // На не-Windows платформах остаётся вариант с управляющим символом.

            if (OperatingSystem.IsWindows())
            {
                Console.Beep(1400, 160);
                System.Threading.Thread.Sleep(180);
                Console.Beep(1400, 160);
                System.Threading.Thread.Sleep(180);
                Console.Beep(1400, 160);
                return;
            }

            Write('\a');
            System.Threading.Thread.Sleep(180);
            Write('\a');
            System.Threading.Thread.Sleep(180);
            Write('\a');
        }
    }
}
