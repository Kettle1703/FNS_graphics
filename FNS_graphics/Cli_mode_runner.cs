using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using FNS_rebuild;

namespace FNS_graphics
{
    internal static class Cli_mode_runner
    {
        const uint Attach_parent_process = 0xFFFFFFFF;
        const string Stochastic_encryption_command = "stochastic-encryption";
        const string Analysis_reports_command = "analysis-fss-reports";

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        static extern uint GetConsoleOutputCP();

        [DllImport("kernel32.dll")]
        static extern uint GetConsoleCP();

        internal static bool TryRun(string[] args, out int exit_code)
        {
            // Запускает CLI-команду, если она передана в аргументах приложения.
            exit_code = 0;
            if (args is null || args.Length == 0)
                return false;

            Bind_console();

            string command = Normalize_command(args[0]);
            string[] command_args = Extract_command_args(args);

            if (Is_command(command, Stochastic_encryption_command, "stochastic", "stoch", "stochastic-test", "стохастика"))
            {
                exit_code = Run_stochastic_encryption(command_args);
                return true;
            }

            if (Is_command(command, Analysis_reports_command, "analysis", "analysis-fss", "analyze", "анализ"))
            {
                exit_code = Run_analysis_reports(command_args);
                return true;
            }

            if (Is_command(command, "help", "--help", "-h", "/?"))
            {
                Print_usage();
                exit_code = 0;
                return true;
            }

            Console.WriteLine($"Неизвестная CLI-команда: {args[0]}");
            Print_usage();
            exit_code = 2;
            return true;
        }

        static int Run_stochastic_encryption(string[] args)
        {
            // Запускает стохастические тесты шифрования с параметрами из командной строки.
            if (Contains_help_argument(args))
            {
                Print_stochastic_usage();
                return 0;
            }

            Stochastic_cli_options options;
            try
            {
                options = Stochastic_cli_options.Parse(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
                Print_stochastic_usage();
                return 2;
            }

            Console.WriteLine("CLI: запуск стохастического тестирования шифрования FNS...");
            Console.WriteLine($"Диапазон длин: {options.Min_length}..{options.Max_length}");
            Console.WriteLine($"Шаг по длине: {options.Length_step}");
            Console.WriteLine($"Тестов на длину: {options.Tests_per_length}");
            Console.WriteLine($"Шаг отчёта прогресса: {options.Progress_step}");
            Console.WriteLine();

            try
            {
                Strategy_wrapper wrapper = Build_fns_wrapper();
                bool success = Stochastic_tests_encryption.Run_round_trip_tests(
                    wrapper,
                    options.Min_length,
                    options.Max_length,
                    options.Tests_per_length,
                    options.Progress_step,
                    options.Length_step);

                Console.WriteLine();
                Console.WriteLine(success
                    ? "Итог: стохастическое тестирование завершено успешно."
                    : "Итог: стохастическое тестирование завершилось с ошибками.");

                return Exit_with_optional_pause(success ? 0 : 1, options.Pause_on_exit);
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Итог: стохастическое тестирование упало с исключением.");
                Console.WriteLine(ex);
                return Exit_with_optional_pause(1, options.Pause_on_exit);
            }
        }

        static int Run_analysis_reports(string[] args)
        {
            // Запускает расчёт листов анализа ФСС с записью данных в Excel.
            if (Contains_help_argument(args))
            {
                Print_analysis_usage();
                return 0;
            }

            if (args.Length > 0)
            {
                Console.WriteLine("Команда analysis-fss-reports не принимает параметры.");
                Console.WriteLine();
                Print_analysis_usage();
                return 2;
            }

            Console.WriteLine("CLI: запуск построения Excel-отчётов анализа ФСС...");
            Strategy_wrapper wrapper = Build_fns_wrapper();
            Analysis.Run_three_analysis_reports(wrapper);
            Console.WriteLine("CLI: построение Excel-отчётов анализа завершено.");
            return 0;
        }

        static int Exit_with_optional_pause(int exit_code, bool pause_on_exit)
        {
            // Завершает команду и при необходимости ждёт Enter.
            if (pause_on_exit)
            {
                Console.WriteLine();
                Console.Write("Нажмите Enter для выхода...");
                Console.ReadLine();
            }

            return exit_code;
        }

        static Strategy_wrapper Build_fns_wrapper()
        {
            // Создаёт рабочую стратегию шифрования ФСС для CLI-задач.
            return new Strategy_wrapper(new Factorial_strategy());
        }

        static void Bind_console()
        {
            // Привязывает WinExe-процесс к консоли PowerShell, чтобы видеть вывод CLI.
            if (!AttachConsole(Attach_parent_process))
                AllocConsole();

            Sync_console_encoding_with_host();
            Rebind_standard_streams();
        }

        static void Sync_console_encoding_with_host()
        {
            // Синхронизирует кодировку .NET-консоли с активной кодировкой хоста.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            uint output_code_page = GetConsoleOutputCP();
            if (output_code_page > 0)
                Console.OutputEncoding = Encoding.GetEncoding((int)output_code_page);

            uint input_code_page = GetConsoleCP();
            if (input_code_page > 0)
                Console.InputEncoding = Encoding.GetEncoding((int)input_code_page);
        }

        static void Rebind_standard_streams()
        {
            // Переподключает стандартные потоки вывода/ошибок после AttachConsole.
            Encoding output_encoding = Get_stream_encoding_without_bom(Console.OutputEncoding);
            StreamWriter standard_output = new(Console.OpenStandardOutput(), output_encoding) { AutoFlush = true };
            Console.SetOut(standard_output);

            StreamWriter standard_error = new(Console.OpenStandardError(), output_encoding) { AutoFlush = true };
            Console.SetError(standard_error);
        }

        static Encoding Get_stream_encoding_without_bom(Encoding source)
        {
            // Возвращает кодировку для консольного потока без BOM-маркера.
            if (source.CodePage == Encoding.UTF8.CodePage)
                return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

            return source;
        }

        static string[] Extract_command_args(string[] args)
        {
            // Возвращает аргументы без имени команды.
            if (args.Length <= 1)
                return [];

            string[] result = new string[args.Length - 1];
            Array.Copy(args, 1, result, 0, result.Length);
            return result;
        }

        static bool Contains_help_argument(string[] args)
        {
            // Проверяет наличие аргумента справки в списке параметров команды.
            for (int i = 0; i < args.Length; i++)
            {
                if (Is_command(args[i], "help", "--help", "-h", "/?"))
                    return true;
            }

            return false;
        }

        static string Normalize_command(string input)
        {
            // Приводит имя команды к каноническому виду для сравнения.
            return (input ?? "").Trim().ToLowerInvariant();
        }

        static bool Is_command(string input, params string[] aliases)
        {
            // Проверяет совпадение команды с любым допустимым псевдонимом.
            for (int i = 0; i < aliases.Length; i++)
            {
                if (string.Equals(input, aliases[i], StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        static void Print_usage()
        {
            // Печатает общую справку по доступным CLI-командам.
            Console.WriteLine("Доступные CLI-команды:");
            Console.WriteLine($"  {Stochastic_encryption_command}  - стохастические тесты Encrypt/Decrypt для FNS.");
            Console.WriteLine($"  {Analysis_reports_command}      - расчёт Excel-листов анализа ФСС.");
            Console.WriteLine("  help                            - вывести эту справку.");
            Console.WriteLine();
            Console.WriteLine("Псевдонимы команд: stochastic, analysis, help.");
            Console.WriteLine();
            Print_stochastic_usage();
            Console.WriteLine();
            Print_analysis_usage();
        }

        static void Print_stochastic_usage()
        {
            // Печатает справку по команде стохастического тестирования.
            Console.WriteLine("Команда: stochastic-encryption");
            Console.WriteLine("Пример запуска:");
            Console.WriteLine("  dotnet .\\FNS_graphics\\bin\\Debug\\net8.0-windows\\FNS_graphics.dll stochastic-encryption --tests-per-length 3 --length-step 3 --progress-step 100 --pause-on-exit");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            Console.WriteLine("  --min-length N        Минимальная длина тестируемой строки (по умолчанию 1).");
            Console.WriteLine("  --max-length N        Максимальная длина тестируемой строки (по умолчанию 5000).");
            Console.WriteLine("  --tests-per-length N  Количество раундов Encrypt->Decrypt на каждую длину (по умолчанию 1).");
            Console.WriteLine("  --progress-step N     Печать прогресса после каждых N обработанных длин (по умолчанию 500).");
            Console.WriteLine("  --length-step N       Шаг перебора длин (по умолчанию 1).");
            Console.WriteLine("  --pause-on-exit       Ждать Enter перед завершением процесса.");
            Console.WriteLine("  --help                Показать справку только по этой команде.");
            Console.WriteLine();
            Console.WriteLine("Поддерживаются формы: --name value и --name=value.");
        }

        static void Print_analysis_usage()
        {
            // Печатает справку по команде построения листов анализа.
            Console.WriteLine("Команда: analysis-fss-reports");
            Console.WriteLine("Пример запуска:");
            Console.WriteLine("  dotnet .\\FNS_graphics\\bin\\Debug\\net8.0-windows\\FNS_graphics.dll analysis-fss-reports");
            Console.WriteLine("Параметры не требуются.");
        }

        sealed class Stochastic_cli_options
        {
            internal int Min_length { get; private init; } = Stochastic_tests_encryption.Fast_min_length;
            internal int Max_length { get; private init; } = Stochastic_tests_encryption.Fast_max_length_with_blocks;
            internal int Tests_per_length { get; private init; } = Stochastic_tests_encryption.Fast_tests_per_length;
            internal int Progress_step { get; private init; } = Stochastic_tests_encryption.Fast_progress_step;
            internal int Length_step { get; private init; } = Stochastic_tests_encryption.Fast_length_step;
            internal bool Pause_on_exit { get; private init; }

            internal static Stochastic_cli_options Parse(string[] args)
            {
                // Разбирает параметры стохастического теста из аргументов командной строки.
                int min_length = Stochastic_tests_encryption.Fast_min_length;
                int max_length = Stochastic_tests_encryption.Fast_max_length_with_blocks;
                int tests_per_length = Stochastic_tests_encryption.Fast_tests_per_length;
                int progress_step = Stochastic_tests_encryption.Fast_progress_step;
                int length_step = Stochastic_tests_encryption.Fast_length_step;
                bool pause_on_exit = false;

                for (int i = 0; i < args.Length; i++)
                {
                    string arg = args[i];

                    if (string.Equals(arg, "--pause-on-exit", StringComparison.OrdinalIgnoreCase))
                    {
                        pause_on_exit = true;
                        continue;
                    }

                    if (Try_read_int_option(args, ref i, "--min-length", arg, out int min))
                    {
                        min_length = min;
                        continue;
                    }

                    if (Try_read_int_option(args, ref i, "--max-length", arg, out int max))
                    {
                        max_length = max;
                        continue;
                    }

                    if (Try_read_int_option(args, ref i, "--tests-per-length", arg, out int tests))
                    {
                        tests_per_length = tests;
                        continue;
                    }

                    if (Try_read_int_option(args, ref i, "--progress-step", arg, out int progress))
                    {
                        progress_step = progress;
                        continue;
                    }

                    if (Try_read_int_option(args, ref i, "--length-step", arg, out int step))
                    {
                        length_step = step;
                        continue;
                    }

                    throw new ArgumentException($"Неизвестный параметр: {arg}");
                }

                Validate(min_length, max_length, tests_per_length, progress_step, length_step);

                return new Stochastic_cli_options
                {
                    Min_length = min_length,
                    Max_length = max_length,
                    Tests_per_length = tests_per_length,
                    Progress_step = progress_step,
                    Length_step = length_step,
                    Pause_on_exit = pause_on_exit
                };
            }

            static bool Try_read_int_option(string[] args, ref int index, string option_name, string current_arg, out int value)
            {
                // Пытается прочитать целочисленный параметр в формате --name value или --name=value.
                value = 0;

                string prefix = option_name + "=";
                if (current_arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (!int.TryParse(current_arg[prefix.Length..], out value))
                        throw new ArgumentException($"Для {option_name} указано не число: {current_arg[prefix.Length..]}");
                    return true;
                }

                if (!string.Equals(current_arg, option_name, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (index + 1 >= args.Length)
                    throw new ArgumentException($"Для {option_name} нужно указать число.");

                index++;
                if (!int.TryParse(args[index], out value))
                    throw new ArgumentException($"Для {option_name} указано не число: {args[index]}");

                return true;
            }

            static void Validate(int min_length, int max_length, int tests_per_length, int progress_step, int length_step)
            {
                // Проверяет диапазоны значений CLI-параметров стохастического теста.
                if (min_length < 1)
                    throw new ArgumentOutOfRangeException(nameof(min_length), "Минимальная длина должна быть >= 1.");

                if (max_length < min_length)
                    throw new ArgumentOutOfRangeException(nameof(max_length), "Максимальная длина должна быть >= минимальной.");

                if (tests_per_length < 1)
                    throw new ArgumentOutOfRangeException(nameof(tests_per_length), "Тестов на длину должно быть >= 1.");

                if (progress_step < 1)
                    throw new ArgumentOutOfRangeException(nameof(progress_step), "Шаг прогресса должен быть >= 1.");

                if (length_step < 1)
                    throw new ArgumentOutOfRangeException(nameof(length_step), "Шаг длины должен быть >= 1.");
            }
        }
    }
}
