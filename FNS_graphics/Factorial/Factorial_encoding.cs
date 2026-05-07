using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
namespace FNS_rebuild
{
    internal class Factorial_encoding
    {
        public static Dictionary<char, Digit> char_to_number = [];  // связь символа из алфавита и его порядкового номера в алфавите

        // [НЕ ИСПОЛЬЗУЕТСЯ В ТЕКУЩЕЙ ВЕРСИИ]
        // Поля factorial_table, factorial_base, factorial_length_to_index и методы Create_factorial_table,
        // Rebuild_length_index, Convert_to_int нужны были старой реализации Convert_to_factorial_system,
        // которая раскладывала число делением на убывающие факториалы.
        // После перехода на алгоритм "снизу вверх" (Long_math.Divide_by_int с возрастающим делителем)
        // и схему Горнера в Factorial_decoding эти структуры в шифровании/дешифровании не задействованы.
        // Оставлены для будущих стратегий, диагностики (Analysis.Print_factorial_table) или экспериментов.

        public static List<Digit[]> factorial_table = [];  // [НЕ ИСПОЛЬЗУЕТСЯ] вектор всех факториалов
        public static Digit factorial_base = 0;  // [НЕ ИСПОЛЬЗУЕТСЯ] основание системы счисления, в которой посчитана таблица факториалов
        public static Dictionary<int, int> factorial_length_to_index = [];  // [НЕ ИСПОЛЬЗУЕТСЯ] связывает длину факториала и индекс в таблице факториалов

        // [НЕ ИСПОЛЬЗУЕТСЯ В ТЕКУЩЕЙ ВЕРСИИ] см. блок-комментарий выше
        public static void Create_factorial_table(int max_length)
        {
            // создаёт или продолжает таблицу факториалов до длины max_length разрядов
            if (max_length < 1)
                return;

            if (factorial_base != Factorial_strategy.power)
            {
                // если основание системы счисления таблицы факториалов не совпадает с текущим основание
                factorial_table.Clear();
                factorial_length_to_index.Clear();
                factorial_base = Factorial_strategy.power;
            }

            Digit[] current;
            int n;

            if (factorial_table.Count == 0)
            {
                current = [1];
                factorial_table.Add(current);
                n = 2;
            }
            else
            {
                current = factorial_table[^1];
                n = factorial_table.Count + 1;
            }

            if (current.Length > max_length)
                return;

            while (n <= Digit.MaxValue)
            {
                Digit[] next = Long_math.Multiply_by_digit(current, (Digit)n, 0);
                if (next.Length > max_length)
                    break;

                factorial_table.Add(next);
                current = next;
                n++;
            }

            Rebuild_length_index();
        }

        // [НЕ ИСПОЛЬЗУЕТСЯ В ТЕКУЩЕЙ ВЕРСИИ] см. блок-комментарий выше
        static void Rebuild_length_index()
        {
            // строит словарь: длина -> индекс последнего факториала с такой длиной
            factorial_length_to_index.Clear();
            if (factorial_table.Count == 0)
                return;

            int max_len = factorial_table[^1].Length;
            int index = 0;

            for (int length = 1; length <= max_len; length++)
            {
                while (index < factorial_table.Count && factorial_table[index].Length <= length)
                    index++;

                int value = index - 1;
                if (value < 0)
                    value = 0;

                factorial_length_to_index[length] = value;
            }
        }

        // [НЕ ИСПОЛЬЗУЕТСЯ В ТЕКУЩЕЙ ВЕРСИИ] см. блок-комментарий выше
        static int Convert_to_int(Digit[] digits)
        {
            // переводит массив разрядов в int (обычная система), порядок разрядов инвертированный
            // нужен был старой реализации для получения коэффициента factoradic
            int base_value = Factorial_strategy.power;
            int value = 0;
            for (int i = digits.Length - 1; i >= 0; i--)
                value = value * base_value + digits[i];

            return value;
        }

        public static Digit[] Convert_to_factorial_system(Digit[] value)
        {
            // переводит число в факториальную систему счисления, результат в инвертированном порядке
            // (result[0] = c_1, result[1] = c_2, ..., result[M-1] = c_M)
            //
            // алгоритм "снизу вверх": последовательно делим число на 2, 3, 4, ...
            // остаток на каждом шаге — это коэффициент c_i при i!.
            // Правило 0 <= c_i <= i соблюдается автоматически: c_i — это остаток от деления на (i+1).
            // Сложность: O(M^2 log M) digit-операций; таблица факториалов не требуется.
            if (value.Length == 0)
                return [0];
            if (value.Length == 1 && value[0] == 0)
                return [0];

            List<Digit> result = [];
            Digit[] current = value;
            int divisor = 2;

            while (current.Length > 1 || current[0] != 0)
            {
                current = Long_math.Divide_by_int(current, divisor, out int remainder);
                result.Add((Digit)remainder);
                divisor++;
            }

            return result.ToArray();
        }


    }
}
