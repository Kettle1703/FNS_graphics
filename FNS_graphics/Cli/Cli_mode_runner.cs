using System;
using System.Diagnostics;
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

            Console.WriteLine("CLI: запуск стохастического тестирования шифрования...");
            Console.WriteLine($"Ядро шифрования: {options.Core_display_name}");
            Console.WriteLine($"Диапазон длин: {options.Min_length}..{options.Max_length}");
            Console.WriteLine($"Шаг по длине: {options.Length_step}");
            Console.WriteLine($"Тестов на длину: {options.Tests_per_length}");
            Console.WriteLine($"Шаг отчёта прогресса: {options.Progress_step}");
            Console.WriteLine($"Длина открытого блока: {(options.Block_plain_text_length > 0 ? options.Block_plain_text_length.ToString() : "отключено")}");
            Console.WriteLine();

            try
            {
                Strategy_wrapper wrapper = Build_strategy_wrapper(options.Encryption_core);
                Cipher_options? cipher_options = Build_stochastic_cipher_options(options);
                bool success = Stochastic_tests_encryption.Run_round_trip_tests(
                    wrapper,
                    options.Min_length,
                    options.Max_length,
                    options.Tests_per_length,
                    options.Progress_step,
                    options.Length_step,
                    cipher_options);

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

            Analysis_report_batch_options options;
            try
            {
                options = Parse_analysis_options(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
                Print_analysis_usage();
                return 2;
            }

            Console.WriteLine("CLI: запуск построения Excel-отчётов анализа ФСС...");
            Console.WriteLine($"Тип отчёта: {Format_analysis_report_kind(options.Report_kind)}");
            Console.WriteLine($"Папка вывода: {options.Output_dir}");
            Console.WriteLine($"Диапазон длин: {options.Min_length}..{options.Max_length}");
            Console.WriteLine($"Шаг длины: {options.Length_step}");
            Console.WriteLine($"Повторов Encrypt/Decrypt на длину: {options.Tests_per_length}");
            Console.WriteLine($"Парных тестов лавины/ключа на длину: {options.Avalanche_tests_per_length}");
            Console.WriteLine($"Тестов помехоустойчивости на длину: {options.Interference_tests_per_length}");
            Console.WriteLine($"Повышенный приоритет процесса: {(options.Use_high_process_priority ? "да" : "нет")}");
            Console.WriteLine();

            Process current_process = Process.GetCurrentProcess();
            ProcessPriorityClass original_priority = current_process.PriorityClass;

            try
            {
                if (options.Use_high_process_priority)
                    current_process.PriorityClass = ProcessPriorityClass.High;

                Strategy_wrapper wrapper = Build_fns_wrapper();
                Analysis.Run_three_analysis_reports(wrapper, options);
                Console.WriteLine("CLI: построение Excel-отчётов анализа завершено.");
                return 0;
            }
            finally
            {
                if (options.Use_high_process_priority)
                {
                    try
                    {
                        current_process.PriorityClass = original_priority;
                    }
                    catch
                    {
                        // Возврат приоритета best-effort: процесс уже завершает CLI-команду.
                    }
                }
            }
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

        static Strategy_wrapper Build_strategy_wrapper(Encryption_core_kind encryption_core)
        {
            return encryption_core switch
            {
                Encryption_core_kind.KuznyechikCtr => new Strategy_wrapper(new Kuznyechik_strategy()),
                Encryption_core_kind.AesGcm => new Strategy_wrapper(new Aes_gcm_strategy()),
                _ => Build_fns_wrapper()
            };
        }

        static Cipher_options? Build_stochastic_cipher_options(Stochastic_cli_options options)
        {
            Encryption_core_kind encryption_core = options.Encryption_core;
            if (encryption_core != Encryption_core_kind.KuznyechikCtr &&
                encryption_core != Encryption_core_kind.AesGcm &&
                options.Block_plain_text_length <= 0)
                return null;

            return new Cipher_options
            {
                Block_plain_text_length = encryption_core == Encryption_core_kind.Factorial
                    ? options.Block_plain_text_length
                    : 0,
                Key = "STOCHASTIC_CORE_TEST_KEY_256",
                Enable_round_cipher = encryption_core == Encryption_core_kind.Factorial,
                Encryption_core = encryption_core
            };
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
                Console.OutputEncoding = Get_console_encoding_for_code_page((int)output_code_page);

            uint input_code_page = GetConsoleCP();
            if (input_code_page > 0)
                Console.InputEncoding = Get_console_encoding_for_code_page((int)input_code_page);
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

        static Encoding Get_console_encoding_for_code_page(int code_page)
        {
            // Возвращает кодировку консоли по code page и отключает BOM для UTF-8.
            if (code_page == Encoding.UTF8.CodePage)
                return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

            return Encoding.GetEncoding(code_page);
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

        static bool Try_read_string_option(string[] args, ref int index, string option_name, string current_arg, out string value)
        {
            // Пытается прочитать строковый параметр в формате --name value или --name=value.
            value = string.Empty;

            string prefix = option_name + "=";
            if (current_arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                value = current_arg[prefix.Length..];
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentException($"Для {option_name} нужно указать значение.");
                return true;
            }

            if (!string.Equals(current_arg, option_name, StringComparison.OrdinalIgnoreCase))
                return false;

            if (index + 1 >= args.Length)
                throw new ArgumentException($"Для {option_name} нужно указать значение.");

            index++;
            value = args[index];
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException($"Для {option_name} нужно указать значение.");

            return true;
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
            Console.WriteLine("  --block-length N      Длина открытого блока для ФСС; 0 отключает блочный режим.");
            Console.WriteLine("  --core NAME           Ядро: fns/factorial, kuz/kuznyechik/grasshopper или aes/aes-gcm.");
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
            Console.WriteLine("  dotnet .\\FNS_graphics\\bin\\Debug\\net8.0-windows\\FNS_graphics.dll analysis-fss-reports --type block-length --output-dir \"C:\\data\" --max-length 1500 --tests-per-length 1");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            Console.WriteLine("  --type NAME                         Тип: all, block-length, round-cipher, block-round-matrix, block-size-sweep, encryption-core.");
            Console.WriteLine("  --output-dir PATH                   Папка для xlsx-файлов.");
            Console.WriteLine("  --min-length N                      Минимальная длина строки (по умолчанию 1).");
            Console.WriteLine("  --max-length N                      Максимальная длина строки (по умолчанию 5000).");
            Console.WriteLine("  --length-step N                     Шаг перебора длин сообщений (по умолчанию 1).");
            Console.WriteLine("  --tests-per-length N                Повторов Encrypt/Decrypt на длину (по умолчанию 3).");
            Console.WriteLine("  --avalanche-tests-per-length N      Парных тестов лавины/ключа на длину (по умолчанию 3).");
            Console.WriteLine("  --interference-tests-per-length N   Тестов помехоустойчивости на длину (по умолчанию 3).");
            Console.WriteLine("  --progress-step N                   Шаг отчёта прогресса (по умолчанию 250).");
            Console.WriteLine("  --high-priority                     Поднять приоритет процесса на время анализа.");
            Console.WriteLine();
            Console.WriteLine("Поддерживаются формы: --name value и --name=value.");
        }

        static Analysis_report_batch_options Parse_analysis_options(string[] args)
        {
            Analysis_report_batch_options options = new();

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                if (Try_read_string_option(args, ref i, "--type", arg, out string type) ||
                    Try_read_string_option(args, ref i, "--report", arg, out type))
                {
                    options.Report_kind = Parse_analysis_report_kind(type);
                    continue;
                }

                if (Try_read_string_option(args, ref i, "--output-dir", arg, out string output_dir))
                {
                    options.Output_dir = output_dir;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--min-length", arg, out int min_length))
                {
                    options.Min_length = min_length;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--max-length", arg, out int max_length))
                {
                    options.Max_length = max_length;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--length-step", arg, out int length_step))
                {
                    options.Length_step = length_step;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--tests-per-length", arg, out int tests_per_length))
                {
                    options.Tests_per_length = tests_per_length;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--avalanche-tests-per-length", arg, out int avalanche_tests_per_length))
                {
                    options.Avalanche_tests_per_length = avalanche_tests_per_length;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--interference-tests-per-length", arg, out int interference_tests_per_length))
                {
                    options.Interference_tests_per_length = interference_tests_per_length;
                    continue;
                }

                if (Try_read_int_option(args, ref i, "--progress-step", arg, out int progress_step))
                {
                    options.Progress_step = progress_step;
                    continue;
                }

                if (string.Equals(arg, "--high-priority", StringComparison.OrdinalIgnoreCase))
                {
                    options.Use_high_process_priority = true;
                    continue;
                }

                throw new ArgumentException($"Неизвестный параметр: {arg}");
            }

            options.Validate();
            return options;
        }

        static Analysis_report_kind Parse_analysis_report_kind(string value)
        {
            string normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
            return normalized switch
            {
                "all" or "все" => Analysis_report_kind.All,
                "1" or "block" or "blocks" or "block-length" or "fss-block-length" =>
                    Analysis_report_kind.Fss_block_length,
                "2" or "round" or "round-cipher" or "fss-round-cipher" =>
                    Analysis_report_kind.Fss_round_cipher,
                "matrix" or "block-round" or "block-round-matrix" or "2x2" =>
                    Analysis_report_kind.Fss_block_round_matrix,
                "sweep" or "block-sweep" or "block-size-sweep" or "block-size" =>
                    Analysis_report_kind.Fss_block_size_sweep,
                "3" or "core" or "cores" or "encryption-core" or "core-comparison" =>
                    Analysis_report_kind.Encryption_core,
                _ => throw new ArgumentException($"Неизвестный тип отчёта анализа: {value}")
            };
        }

        static string Format_analysis_report_kind(Analysis_report_kind kind)
        {
            return kind switch
            {
                Analysis_report_kind.Fss_block_length => "сравнение ФСС по длине блока 512/1096",
                Analysis_report_kind.Fss_round_cipher => "сравнение ФСС с раундовым шифрованием и без",
                Analysis_report_kind.Fss_block_round_matrix => "матрица ФСС 512/1096 с раундовым шифрованием и без",
                Analysis_report_kind.Fss_block_size_sweep => "подбор длины блока ФСС при включённом раундовом шифровании",
                Analysis_report_kind.Encryption_core => "сравнение ядер шифрования",
                _ => "все отчёты"
            };
        }

        sealed class Stochastic_cli_options
        {
            internal int Min_length { get; private init; } = Stochastic_tests_encryption.Fast_min_length;
            internal int Max_length { get; private init; } = Stochastic_tests_encryption.Fast_max_length_with_blocks;
            internal int Tests_per_length { get; private init; } = Stochastic_tests_encryption.Fast_tests_per_length;
            internal int Progress_step { get; private init; } = Stochastic_tests_encryption.Fast_progress_step;
            internal int Length_step { get; private init; } = Stochastic_tests_encryption.Fast_length_step;
            internal int Block_plain_text_length { get; private init; }
            internal Encryption_core_kind Encryption_core { get; private init; } = Encryption_core_kind.Factorial;
            internal string Core_display_name => Encryption_core switch
            {
                Encryption_core_kind.KuznyechikCtr => Encryption_core_catalog.Kuznyechik_ctr_display_name,
                Encryption_core_kind.AesGcm => Encryption_core_catalog.Aes_gcm_display_name,
                _ => Encryption_core_catalog.Factorial_display_name
            };
            internal bool Pause_on_exit { get; private init; }

            internal static Stochastic_cli_options Parse(string[] args)
            {
                // Разбирает параметры стохастического теста из аргументов командной строки.
                int min_length = Stochastic_tests_encryption.Fast_min_length;
                int max_length = Stochastic_tests_encryption.Fast_max_length_with_blocks;
                int tests_per_length = Stochastic_tests_encryption.Fast_tests_per_length;
                int progress_step = Stochastic_tests_encryption.Fast_progress_step;
                int length_step = Stochastic_tests_encryption.Fast_length_step;
                int block_plain_text_length = 0;
                Encryption_core_kind encryption_core = Encryption_core_kind.Factorial;
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

                    if (Try_read_int_option(args, ref i, "--block-length", arg, out int block_length) ||
                        Try_read_int_option(args, ref i, "--block-size", arg, out block_length))
                    {
                        block_plain_text_length = block_length;
                        continue;
                    }

                    if (Try_read_string_option(args, ref i, "--core", arg, out string core))
                    {
                        encryption_core = Parse_encryption_core(core);
                        continue;
                    }

                    throw new ArgumentException($"Неизвестный параметр: {arg}");
                }

                Validate(min_length, max_length, tests_per_length, progress_step, length_step, block_plain_text_length);

                return new Stochastic_cli_options
                {
                    Min_length = min_length,
                    Max_length = max_length,
                    Tests_per_length = tests_per_length,
                    Progress_step = progress_step,
                    Length_step = length_step,
                    Block_plain_text_length = block_plain_text_length,
                    Encryption_core = encryption_core,
                    Pause_on_exit = pause_on_exit
                };
            }

            static Encryption_core_kind Parse_encryption_core(string value)
            {
                string normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
                return normalized switch
                {
                    "kuz" or "kuznyechik" or "grasshopper" or "кузнечик" => Encryption_core_kind.KuznyechikCtr,
                    "aes" or "aes-gcm" or "aesgcm" => Encryption_core_kind.AesGcm,
                    "fns" or "factorial" or "фсс" => Encryption_core_kind.Factorial,
                    _ => throw new ArgumentException($"Неизвестное ядро шифрования: {value}")
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

            static bool Try_read_string_option(string[] args, ref int index, string option_name, string current_arg, out string value)
            {
                value = string.Empty;

                string prefix = option_name + "=";
                if (current_arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    value = current_arg[prefix.Length..];
                    if (string.IsNullOrWhiteSpace(value))
                        throw new ArgumentException($"Для {option_name} нужно указать значение.");
                    return true;
                }

                if (!string.Equals(current_arg, option_name, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (index + 1 >= args.Length)
                    throw new ArgumentException($"Для {option_name} нужно указать значение.");

                index++;
                value = args[index];
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentException($"Для {option_name} нужно указать значение.");

                return true;
            }

            static void Validate(int min_length, int max_length, int tests_per_length, int progress_step, int length_step, int block_plain_text_length)
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

                if (block_plain_text_length < 0)
                    throw new ArgumentOutOfRangeException(nameof(block_plain_text_length), "Длина блока должна быть >= 0.");
            }
        }
    }
}
