using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
namespace FNS_rebuild
{
    internal class Factorial_decoding
    {
        public static Dictionary<Digit, char> number_to_char = [];

        public static Digit[] Convert_from_factorial_system(Digit[] input)
        {
            // переводит число из факториальной системы счисления в обычную систему счисления (base = Factorial_strategy.power)
            // все массивы содержат число в инвертированном порядке: input[i-1] = c_i (i-й коэффициент при i!)
            //
            // алгоритм Горнера, основанный на тождестве
            //   N = c_1 + 2·(c_2 + 3·(c_3 + 4·(c_4 + ... + (M-1)·(c_{M-1} + M·c_M))))
            // считаем изнутри: acc = c_M, потом для i = M, M-1, ..., 2 делаем acc = acc * i + c_{i-1}.
            // Используются только Multiply_by_digit и Summa, таблица факториалов не нужна.
            // Сложность: O(M^2 log M) digit-операций.
            if (input.Length == 0)
                return [];

            int base_value = Factorial_strategy.power;

            // acc стартует с c_M, упакованного в base-256 (c_M может быть до M-1, до 1023, влезает в 1-2 разряда)
            Digit highest = input[input.Length - 1];
            Digit[] acc;
            if (highest < base_value)
                acc = [highest];
            else
                acc = [(Digit)(highest % base_value), (Digit)(highest / base_value)];

            for (int i = input.Length; i >= 2; i--)
            {
                acc = Long_math.Multiply_by_digit(acc, (Digit)i, 0);
                Digit c = input[i - 2];
                if (c > 0)
                {
                    Digit[] c_digits;
                    if (c < base_value)
                        c_digits = [c];
                    else
                        c_digits = [(Digit)(c % base_value), (Digit)(c / base_value)];
                    acc = Long_math.Summa(acc, c_digits);
                }
            }

            // обрезаем ведущие нули (на всякий случай — Multiply_by_digit/Summa могут оставить хвостовой 0)
            int last = acc.Length - 1;
            while (last > 0 && acc[last] == 0)
                last--;

            if (last == acc.Length - 1)
                return acc;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(acc, trimmed, trimmed.Length);
            return trimmed;
        }
    }
}
