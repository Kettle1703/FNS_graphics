using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
using System.Text;

namespace FNS_rebuild
{
    internal class Factorial_strategy : IStrategy
    {
        // Класс стратегии шифрования на основе факториальной системы счисления.

        internal static string alphabet = "";  // алфавит, который используется для кодирования/декодирования
        internal static Digit power;  // мощность алфавита
        internal static Dictionary<byte, char> byte_to_char = [];  // связь байта и символа алфавита
        internal static Dictionary<char, byte> char_to_byte = [];  // обратная связь символа и байта

        const int Max_factorial = 1024;  // старший используемый факториал: 1024!
        const int Max_control_bits_per_coef = 2;  // максимум служебных бит на коэффициент сжатия
        const int Max_control_code = 3;  // 00 -> +0, 01 -> +256, 10 -> +512, 11 -> +768
        const int Compression_free_factorial_coefficients = 255;  // первые 255 коэффициентов ФСС всегда <= 255 и не требуют коэффициентов сжатия
        const int Compression_free_mixed_coefficients = Compression_free_factorial_coefficients + 2;  // +2 коэффициента длины в начале общего массива
        const int One_bit_compression_mixed_coefficients = 256;  // следующие 256 коэффициентов требуют только 1 бит сжатия: 0 или +256
        const int Two_bit_compression_start = Compression_free_mixed_coefficients + One_bit_compression_mixed_coefficients;  // дальше снова нужны 2 бита
        internal const int Max_source_length_without_blocks = 1096;  // гарантированная длина без подблоков для текущего формата и мощности алфавита

        // Словарь K(L): длина исходной строки -> сколько коэффициентов ФСС нужно в худшем случае.
        // Нужен для выравнивания потока коэффициентов ФСС без добивки всегда до 1023.
        internal static Dictionary<int, int> source_length_to_factorial_coefficients_count = [];

        // Словарь худших чисел: длина исходной строки -> число power^L - 1.
        // Нужен для быстрого повторного расчёта K(L) для уже встречавшихся длин.
        internal static Dictionary<int, Digit[]> source_length_to_worst_number = [];

        // Термины этого класса:
        // коэффициенты длины: два первых служебных коэффициента (младший и старший байты длины исходной строки);
        // коэффициенты ФСС: коэффициенты при факториалах после перевода длинного числа в факториальную систему;
        // коэффициенты сжатия: 2-битные добавки, позволяющие хранить коэффициенты больше 255.
        const string Seed_alphabet = "~ `!@\"#№$%^?&*()_-+=[]{};:'<,.>/\\|0123456789" +
            "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" +
            "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ" +
            "abcdefghijklmnopqrstuvwxyz" +
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
            "¡¿«»☾☽…†‡•※¤‽" +
            "€£¥¢₽©®™°±×÷§¶µ" +
            "≤≥≠≈∞√∑∏∈∉" +
            "←→↑↓↔↕" +
            "◈◉┌┐└┘├┤┬┴┼" +
            "█▓▒░■□▲▼◆◇●○★☆" +
            "αβγδεζηθικλμνξοπρστυφχψω∆";

        internal Factorial_strategy() : this(Create_default_alphabet())
        {
            // Конструктор по умолчанию: использует встроенный алфавит мощности 256.

        }

        internal Factorial_strategy(string input)
        {
            // Конструктор с пользовательским алфавитом: строит таблицы соответствий символ <-> число.

            alphabet = Unique_alphabet(input);
            power = (Digit)alphabet.Length;

            Factorial_encoding.char_to_number.Clear();
            Factorial_decoding.number_to_char.Clear();
            byte_to_char.Clear();
            char_to_byte.Clear();
            source_length_to_factorial_coefficients_count.Clear();
            source_length_to_worst_number.Clear();
            Coefficient_diffusion.Clear_key_cache();

            Digit counter = 0;
            foreach (char symbol in alphabet)
            {
                Factorial_encoding.char_to_number.Add(symbol, counter);
                Factorial_decoding.number_to_char.Add(counter, symbol);

                if (counter <= byte.MaxValue)
                {
                    byte value = (byte)counter;
                    byte_to_char[value] = symbol;
                    char_to_byte[symbol] = value;
                }

                counter++;
            }

            if (Analysis.debug_mode)
            {
                StringBuilder output = new("Содержание словаря Символ -> число:\n");
                counter = 1;
                foreach (var pair in Factorial_encoding.char_to_number)
                {
                    output.Append($"{pair.Key,-3}{pair.Value,3}    ");
                    if (counter % 9 == 0)
                        output.Append('\n');
                    counter++;
                }
                WriteLine(output.ToString());
            }
        }

        public string Encrypt(string input, Cipher_options options)
        {
            // Шифрование: настройки полностью задаются через Cipher_options.

            options ??= Cipher_options.Default;
            if (options.Use_blocks())
                return Encrypt_by_blocks(input, options);

            return Encrypt_single_block(input, options);
        }

        public string Decrypt(string input, Cipher_options options)
        {
            // Дешифрование: настройки полностью задаются через Cipher_options.

            options ??= Cipher_options.Default;
            if (options.Use_blocks())
                return Decrypt_by_blocks(input, options);

            return Decrypt_single_block(input, options);
        }

        string Encrypt_single_block(string input, Cipher_options options)
        {
            // Шифрует один блок открытого текста в текущем формате ФСС.

            Digit[] source_digits = Long_math.To_array(input);
            Digit[] normalized_source_digits = Trim_high_zeros(source_digits);
            Digit[] factorial_coefficients = Factorial_encoding.Convert_to_factorial_system(normalized_source_digits);
            factorial_coefficients = Pad_factorial_coefficients(factorial_coefficients, source_digits.Length);
            string serialized_coefficients = Serialize_factorial(factorial_coefficients, source_digits.Length);
            return Coefficient_diffusion.Encrypt(serialized_coefficients, options);
        }

        string Decrypt_single_block(string input, Cipher_options options)
        {
            // Дешифрует один блок шифротекста из текущего формата ФСС.

            string serialized_coefficients = Coefficient_diffusion.Decrypt(input, options);
            Digit[] factorial_coefficients = Deserialize_factorial(serialized_coefficients, out int source_text_length);
            Digit[] source_digits = Factorial_decoding.Convert_from_factorial_system(factorial_coefficients);
            source_digits = Restore_length(source_digits, source_text_length);
            return Long_math.From_array(source_digits);
        }

        string Encrypt_by_blocks(string input, Cipher_options options)
        {
            // Блочное шифрование без длины у каждого блока.
            // В заголовке пишутся общая длина исходной строки и длина открытого блока.
            // Длина шифротекста блока вычисляется детерминированно по длине открытого блока.

            int source_text_length = input.Length;
            int block_plain_text_length = options.Block_plain_text_length;
            StringBuilder output = new();

            Write_u16(output, source_text_length);
            Write_u16(output, block_plain_text_length);

            int offset = 0;
            while (offset < source_text_length)
            {
                int current_block_length = block_plain_text_length;
                int remaining = source_text_length - offset;
                if (current_block_length > remaining)
                    current_block_length = remaining;

                string block_source = input.Substring(offset, current_block_length);
                string block_encrypted = Encrypt_single_block(block_source, options);
                output.Append(block_encrypted);

                offset += current_block_length;
            }

            return output.ToString();
        }

        string Decrypt_by_blocks(string input, Cipher_options options)
        {
            // Блочное дешифрование для формата из Encrypt_by_blocks.
            // Блоки читаются подряд по вычисляемой длине шифротекста для каждой длины открытого блока.

            int index = 0;
            int source_text_length = Read_u16(input, ref index);
            int block_plain_text_length = Read_u16(input, ref index);
            StringBuilder output = new(source_text_length);

            int restored_length = 0;
            while (restored_length < source_text_length)
            {
                int current_block_length = block_plain_text_length;
                int remaining = source_text_length - restored_length;
                if (current_block_length > remaining)
                    current_block_length = remaining;

                int encrypted_block_length = Get_ciphertext_length_for_source_length(current_block_length);
                string block_encrypted = input.Substring(index, encrypted_block_length);
                string block_source = Decrypt_single_block(block_encrypted, options);
                output.Append(block_source);

                index += encrypted_block_length;
                restored_length += current_block_length;
            }

            return output.ToString();
        }

        static string Serialize_factorial(Digit[] factorial_coefficients, int source_text_length)
        {
            // Формирует шифротекст из коэффициентов ФСС.
            // В этом формате хранятся две длины:
            // 1) source_text_length: длина исходного сообщения в 2 коэффициентах длины;
            // 2) metadata_coefficients_count: сколько коэффициентов идёт в основном потоке
            //    (2 коэффициента длины + коэффициенты ФСС), хранится в первых 2 символах шифротекста.
            // Дополнительно действует правило оптимизации:
            // для первых Compression_free_mixed_coefficients коэффициентов поток сжатия не пишется;
            // для диапазона 257..512 пишется 1 бит; дальше пишется 2 бита.

            Digit[] mixed_coefficients = With_length_coefficients(factorial_coefficients, source_text_length);
            StringBuilder ciphertext_builder = new();
            Write_u16(ciphertext_builder, mixed_coefficients.Length);

            byte control_byte = 0;
            int control_bit_index = 0;
            StringBuilder compression_stream = new();

            for (int i = 0; i < mixed_coefficients.Length; i++)
            {
                int mixed_coefficient = mixed_coefficients[i];
                int compression_coefficient = mixed_coefficient / power;
                int base_coefficient = mixed_coefficient - compression_coefficient * power;

                ciphertext_builder.Append(Factorial_decoding.number_to_char[(Digit)base_coefficient]);
                int control_bits_count = Get_control_bits_count_for_mixed_index(i);
                if (control_bits_count > 0)
                    Write_control_code(compression_coefficient, control_bits_count, ref control_byte, ref control_bit_index, compression_stream);
            }

            if (control_bit_index > 0)
                compression_stream.Append(byte_to_char[control_byte]);

            ciphertext_builder.Append(compression_stream);
            return ciphertext_builder.ToString();
        }

        static Digit[] Deserialize_factorial(string input, out int source_text_length)
        {
            // Разбирает шифротекст на три вида коэффициентов:
            // коэффициенты длины, коэффициенты ФСС, коэффициенты сжатия.
            // Для первых Compression_free_mixed_coefficients коэффициентов сжатие равно нулю.
            // Для диапазона 257..512 читается 1 бит, дальше читаются 2 бита.

            int index = 0;
            int metadata_coefficients_count = Read_u16(input, ref index);

            Digit[] base_coefficients = new Digit[metadata_coefficients_count];
            for (int i = 0; i < metadata_coefficients_count; i++)
            {
                base_coefficients[i] = Factorial_encoding.char_to_number[input[index]];
                index++;
            }

            Digit[] mixed_coefficients = new Digit[metadata_coefficients_count];
            int bit_index = 8;
            byte control_byte = 0;

            for (int i = 0; i < metadata_coefficients_count; i++)
            {
                int compression_coefficient = 0;
                int control_bits_count = Get_control_bits_count_for_mixed_index(i);
                if (control_bits_count > 0)
                    compression_coefficient = Read_control_code(input, control_bits_count, ref index, ref control_byte, ref bit_index);
                mixed_coefficients[i] = (Digit)(base_coefficients[i] + compression_coefficient * power);
            }

            source_text_length = mixed_coefficients[0] + (mixed_coefficients[1] << 8);
            Digit[] factorial_coefficients = new Digit[mixed_coefficients.Length - 2];
            Array.Copy(mixed_coefficients, 2, factorial_coefficients, 0, factorial_coefficients.Length);
            return factorial_coefficients;
        }

        static void Write_control_code(int compression_coefficient, int control_bits_count, ref byte control_byte, ref int control_bit_index, StringBuilder compression_stream)
        {
            // Упаковывает один коэффициент сжатия в служебный поток.
            // control_bits_count задаёт, сколько бит реально нужно для текущего коэффициента.

            for (int bit = 0; bit < control_bits_count; bit++)
            {
                if ((compression_coefficient & (1 << bit)) != 0)
                    control_byte = (byte)(control_byte + (1 << control_bit_index));

                control_bit_index++;
                if (control_bit_index == 8)
                {
                    compression_stream.Append(byte_to_char[control_byte]);
                    control_byte = 0;
                    control_bit_index = 0;
                }
            }
        }

        static int Read_control_code(string input, int control_bits_count, ref int index, ref byte control_byte, ref int bit_index)
        {
            // Читает из служебного потока один коэффициент сжатия.
            // control_bits_count должен совпадать с тем, что использовалось при записи.

            int compression_coefficient = 0;
            for (int bit = 0; bit < control_bits_count; bit++)
            {
                if (bit_index == 8)
                {
                    control_byte = char_to_byte[input[index]];
                    index++;
                    bit_index = 0;
                }

                if ((control_byte & (1 << bit_index)) != 0)
                    compression_coefficient += 1 << bit;

                bit_index++;
            }

            return compression_coefficient;
        }

        static void Write_u16(StringBuilder output, int value)
        {
            // Служебная запись uint16 в 2 символа алфавита (младший и старший байт).

            byte low = (byte)(value & 255);
            byte high = (byte)((value >> 8) & 255);
            output.Append(byte_to_char[low]);
            output.Append(byte_to_char[high]);
        }

        static int Read_u16(string input, ref int index)
        {
            // Служебное чтение uint16 из 2 символов алфавита (младший и старший байт).

            byte low = char_to_byte[input[index]];
            byte high = char_to_byte[input[index + 1]];
            index += 2;
            return low + (high << 8);
        }

        static int Get_ciphertext_length_for_source_length(int source_text_length)
        {
            // Возвращает длину шифротекста одного блока для заданной длины исходного блока.
            // Формула для одного блока:
            // 2 символа заголовка metadata_count + metadata_count базовых коэффициентов +
            // ceil(control_bits_count / 8) символов потока коэффициентов сжатия.
            // metadata_count = 2 коэффициента длины + K(L) коэффициентов ФСС.
            // control_bits_count считается по тем же диапазонам, что используются в Serialize_factorial.

            int factorial_coefficients_count = Get_required_factorial_coefficients_count(source_text_length);
            int metadata_coefficients_count = factorial_coefficients_count + 2;
            int control_bits_count = Get_control_bits_count_for_mixed_coefficients_count(metadata_coefficients_count);

            int compression_stream_length = (control_bits_count + 7) / 8;
            return 2 + metadata_coefficients_count + compression_stream_length;
        }

        static int Get_control_bits_count_for_mixed_index(int mixed_index)
        {
            // Возвращает битность коэффициента сжатия по позиции в общем массиве.
            // 0..256: сжатие не нужно; 257..512: нужен 1 бит; 513 и выше: нужны 2 бита.

            if (mixed_index < Compression_free_mixed_coefficients)
                return 0;

            if (mixed_index < Two_bit_compression_start)
                return 1;

            return Max_control_bits_per_coef;
        }

        static int Get_control_bits_count_for_mixed_coefficients_count(int mixed_coefficients_count)
        {
            // Считает суммарное число бит потока сжатия для блока известной длины.
            // Используется при блочном дешифровании, чтобы заранее отрезать шифроблок.

            int result = 0;
            for (int i = Compression_free_mixed_coefficients; i < mixed_coefficients_count; i++)
                result += Get_control_bits_count_for_mixed_index(i);

            return result;
        }

        static Digit[] Trim_high_zeros(Digit[] input)
        {
            // Удаляет хвостовые нули у длинного числа (в старших разрядах).

            int last = input.Length - 1;
            while (last > 0 && input[last] == 0)
                last--;

            if (last == input.Length - 1)
                return input;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(input, trimmed, trimmed.Length);
            return trimmed;
        }

        static Digit[] Restore_length(Digit[] input, int length)
        {
            // Восстанавливает длину массива разрядов: добавляет недостающие старшие нули.

            if (input.Length >= length)
                return input;

            Digit[] restored = new Digit[length];
            Array.Copy(input, restored, input.Length);
            return restored;
        }

        static Digit[] Pad_factorial_coefficients(Digit[] factorial_coefficients, int source_text_length)
        {
            // Выравнивание коэффициентов ФСС до K(L), где K(L) зависит от длины исходной строки.
            // Нулевые добавки пишутся в старшие коэффициенты ФСС и не меняют число.

            int required_count = Get_required_factorial_coefficients_count(source_text_length);
            if (factorial_coefficients.Length >= required_count)
                return factorial_coefficients;

            Digit[] padded = new Digit[required_count];
            Array.Copy(factorial_coefficients, padded, factorial_coefficients.Length);
            return padded;
        }

        static int Get_required_factorial_coefficients_count(int source_text_length)
        {
            // Возвращает K(L) из словаря, при отсутствии — вычисляет и кэширует.

            if (source_length_to_factorial_coefficients_count.TryGetValue(source_text_length, out int cached))
                return cached;

            int calculated = Calculate_required_factorial_coefficients_count(source_text_length);
            source_length_to_factorial_coefficients_count[source_text_length] = calculated;
            return calculated;
        }

        static int Calculate_required_factorial_coefficients_count(int source_text_length)
        {
            // Считает K(L) по худшему числу длины L.

            Digit[] worst_number = Get_worst_number_for_source_length(source_text_length);
            Digit[] worst_factorial_coefficients = Factorial_encoding.Convert_to_factorial_system(worst_number);
            return worst_factorial_coefficients.Length;
        }

        static Digit[] Get_worst_number_for_source_length(int source_text_length)
        {
            // Возвращает худшее число для длины L из словаря, при отсутствии — создаёт и кэширует.

            if (source_length_to_worst_number.TryGetValue(source_text_length, out Digit[]? cached) && cached is not null)
                return cached;

            Digit[] created = Build_worst_number_for_source_length(source_text_length);
            source_length_to_worst_number[source_text_length] = created;
            return created;
        }

        static Digit[] Build_worst_number_for_source_length(int source_text_length)
        {
            // Строит число power^L - 1 как массив из L разрядов со значением power-1.

            if (source_text_length <= 0)
                return [];

            Digit max_digit = (Digit)(power - 1);
            Digit[] result = new Digit[source_text_length];
            Array.Fill(result, max_digit);
            return result;
        }

        static Digit[] With_length_coefficients(Digit[] factorial_coefficients, int source_text_length)
        {
            // Формирует общий массив коэффициентов:
            // сначала два коэффициента длины, затем коэффициенты ФСС.

            Digit[] mixed_coefficients = new Digit[factorial_coefficients.Length + 2];
            mixed_coefficients[0] = (Digit)(source_text_length & 255);
            mixed_coefficients[1] = (Digit)((source_text_length >> 8) & 255);
            Array.Copy(factorial_coefficients, 0, mixed_coefficients, 2, factorial_coefficients.Length);
            return mixed_coefficients;
        }

        static string Unique_alphabet(string input)
        {
            // Удаляет повторяющиеся символы из алфавита, сохраняя исходный порядок.

            HashSet<char> used = [];
            StringBuilder result = new();

            foreach (char symbol in input)
            {
                if (used.Add(symbol))
                    result.Append(symbol);
            }

            return result.ToString();
        }

        static string Create_default_alphabet()
        {
            // Строит дефолтный алфавит:
            // Seed_alphabet уже содержит 256 уникальных символов.
            // Здесь только удаление повторов на случай ручного редактирования строки.

            return Unique_alphabet(Seed_alphabet);
        }
    }
}
