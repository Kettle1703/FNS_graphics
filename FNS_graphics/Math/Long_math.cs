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
    internal class Long_math
    {
        // класс реализующий длинную арифметику (работает только с целыми положительными числами)
        private static int basis_num_sys = Factorial_strategy.power;

        internal static Digit[] To_array(string input)
        {
            // каждый символ исходной строки преобразуется в разряд числа в длинной записи
            // считается, что у числа изначально инвертирован порядок
            Digit[] result = new Digit[input.Length];
            for (int i = 0; i < input.Length; i++)
                result[i] = Factorial_encoding.char_to_number[input[i]];
            if (Analysis.debug_mode)
            {
                WriteLine($"Изначально было передано: {input}");
                Analysis.Print(result);
            }
            return result;
        }

        internal static string From_array(Digit[] input)
        {
            StringBuilder result = new();
            for (int i = 0; i < input.Length; i++)
                result.Append(Factorial_decoding.number_to_char[input[i]]);
            if (Analysis.debug_mode)
            {
                Write($"Изначально было передано: ");
                Analysis.Print(input);
                WriteLine($"{result}");
            }
            return result.ToString();
        }

        internal static Digit[] Summa(Digit[] summand_1, Digit[] summand_2)
        {
            // суммирование столбиком, все числа передаются с инвертированным порядком
            if (summand_2.Length > summand_1.Length)  // хотим, чтобы summand_1 был длиннее 
                (summand_1, summand_2) = (summand_2, summand_1);

            int max_len = summand_1.Length;  // теперь summand_1 длиннее 
            int min_len = summand_2.Length;
            int carry = 0, i = 0, sum;
            Digit[] result = new Digit[max_len];

            for (; i < min_len; i++)  // разряды есть у обоих массивов 
            {
                sum = summand_1[i] + summand_2[i] + carry;
                if (sum >= basis_num_sys)
                {
                    sum -= basis_num_sys;
                    carry = 1;
                }
                else
                    carry = 0;
                result[i] = (Digit)sum;
            }

            if (carry == 0)  // нет переноса разряда, просто копируем остаток большего числа в ответ 
            {
                Array.Copy(summand_1, i, result, i, max_len - i);
                return result;
            }

            for (; i < max_len && summand_1[i] == basis_num_sys - 1; i++)  // разряды, которые есть только у большего числа
                result[i] = 0;

            if (i < max_len)
            {
                result[i] = (Digit)(summand_1[i] + 1);
                i++;
                Array.Copy(summand_1, i, result, i, max_len - i);
                return result;
            }

            Digit[] extended = new Digit[max_len + 1];  // расширенный ответ
            Array.Copy(result, extended, max_len);
            extended[max_len] = 1;
            return extended;
        }

        internal static Digit[] Multiply_by_digit(Digit[] number, Digit multiplier, int zero_shift)
        {
            // умножение числа в инвертированном виде на один разряд с добавлением нулей для сдвига
            if (multiplier == 0 || number.Length == 0)
                return new Digit[1];

            if (multiplier == 1)
            {
                Digit[] result_copy = new Digit[number.Length + zero_shift];
                Array.Copy(number, 0, result_copy, zero_shift, number.Length);
                return result_copy;
            }

            Digit[] result = new Digit[number.Length + zero_shift];
            int base_value = basis_num_sys;
            long carry = 0;

            for (int i = 0; i < number.Length; i++)
            {
                long product = (long)number[i] * multiplier + carry;
                long quotient = Math.DivRem(product, base_value, out long rem);
                result[i + zero_shift] = (Digit)rem;
                carry = quotient;
            }

            if (carry == 0)
                return result;

            int extra_len = 0;
            long temp = carry;
            while (temp > 0)
            {
                temp /= base_value;
                extra_len++;
            }

            Digit[] extended = new Digit[result.Length + extra_len];
            Array.Copy(result, extended, result.Length);
            int index = result.Length;
            while (carry > 0)
            {
                long quotient = Math.DivRem(carry, base_value, out long rem);
                extended[index] = (Digit)rem;
                index++;
                carry = quotient;
            }
            return extended;
        }

        internal static Digit[] Multiply(Digit[] multiplicand, Digit[] multiplier)
        {
            // умножение двух чисел столбиком, числа передаются в инвертированном порядке
            if (multiplicand.Length == 0 || multiplier.Length == 0)
                return new Digit[1];
            if (multiplicand.Length == 1 && multiplicand[0] == 0)
                return new Digit[1];
            if (multiplier.Length == 1 && multiplier[0] == 0)
                return new Digit[1];

            if (multiplier.Length > multiplicand.Length)  // хотим, чтобы multiplicand был длиннее
                (multiplicand, multiplier) = (multiplier, multiplicand);

            Digit[] result = new Digit[1];

            for (int i = 0; i < multiplier.Length; i++)
            {
                Digit multiplier_digit = multiplier[i];
                if (multiplier_digit == 0)
                    continue;

                Digit[] partial = Multiply_by_digit(multiplicand, multiplier_digit, i);
                result = Summa(result, partial);
            }

            int last = result.Length - 1;
            while (last > 0 && result[last] == 0)
                last--;

            if (last == result.Length - 1)
                return result;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(result, trimmed, trimmed.Length);
            return trimmed;
        }

        internal static bool Less_than(Digit[] left, Digit[] right)
        {
            // проверяет, что первое число в инвертированной записи меньше второго
            if (left.Length != right.Length)
                return left.Length < right.Length;

            for (int i = left.Length - 1; i >= 0; i--)
            {
                Digit l = left[i];
                Digit r = right[i];
                if (l != r)
                    return l < r;
            }

            return false;
        }

        internal static Digit[] Difference(Digit[] minuend, Digit[] subtrahend)
        {
            // разность столбиком, числа передаются в инвертированном порядке
            if (Less_than(minuend, subtrahend))
                return minuend;

            int max_len = minuend.Length;
            int min_len = subtrahend.Length;
            int borrow = 0;
            int i = 0;
            Digit[] result = new Digit[max_len];

            for (; i < min_len; i++)
            {
                int diff = minuend[i] - subtrahend[i] - borrow;
                if (diff < 0)
                {
                    diff += basis_num_sys;
                    borrow = 1;
                }
                else
                    borrow = 0;
                result[i] = (Digit)diff;
            }

            if (borrow == 0)
            {
                Array.Copy(minuend, i, result, i, max_len - i);
            }
            else
            {
                for (; i < max_len && minuend[i] == 0; i++)
                    result[i] = (Digit)(basis_num_sys - 1);

                if (i < max_len)
                {
                    result[i] = (Digit)(minuend[i] - 1);
                    i++;
                    Array.Copy(minuend, i, result, i, max_len - i);
                }
            }

            int last = result.Length - 1;
            while (last > 0 && result[last] == 0)
                last--;

            if (last == result.Length - 1)
                return result;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(result, trimmed, trimmed.Length);
            return trimmed;
        }

        internal static Digit[] Divide(Digit[] dividend, Digit[] divisor, out Digit[] quotient)
        {
            // деление столбиком без дробной части, возвращает остаток, частное выдаёт через out
            // если деление не выполняется (делитель больше делимого или делитель 0), в quotient кладётся dividend
            if (dividend.Length == 0 || divisor.Length == 0)
            {
                quotient = [0];
                return new Digit[1];
            }
            if (dividend.Length == 1 && dividend[0] == 0)
            {
                quotient = [0];
                return new Digit[1];
            }
            if (divisor.Length == 1 && divisor[0] == 0)  // деление на 0
            {
                quotient = dividend;
                return dividend;
            }
            if (Less_than(dividend, divisor))
            {
                quotient = dividend;
                return dividend;
            }
            if (divisor.Length == 1 && divisor[0] == 1)  // деление на 1
            {
                quotient = dividend;
                return new Digit[1];
            }

            int max_shift = dividend.Length - divisor.Length;
            quotient = new Digit[max_shift + 1];
            Digit[] remainder = dividend;  // остаток от деления 

            for (int shift = max_shift; shift >= 0; shift--)
            {
                int low = 0;
                int high = basis_num_sys - 1;
                int best = 0;
                Digit[] best_product = new Digit[1];

                while (low <= high)
                {
                    int mid = (low + high) / 2;
                    Digit[] product = Multiply_by_digit(divisor, (Digit)mid, shift);
                    if (Less_than(remainder, product))
                    {
                        high = mid - 1;
                    }
                    else
                    {
                        best = mid;
                        best_product = product;
                        low = mid + 1;
                    }
                }

                if (best != 0)
                {
                    quotient[shift] = (Digit)best;
                    remainder = Difference(remainder, best_product);
                }
            }

            int last = quotient.Length - 1;
            while (last > 0 && quotient[last] == 0)
                last--;

            if (last < quotient.Length - 1)
            {
                Digit[] trimmed = new Digit[last + 1];
                Array.Copy(quotient, trimmed, trimmed.Length);
                quotient = trimmed;
            }

            return remainder;
        }

        internal static Digit[] Divide_by_int(Digit[] dividend, int divisor, out int remainder)
        {
            // деление длинного числа на маленький делитель int (быстрее, чем общий Divide)
            // делитель должен быть положительным; делимое в инвертированном порядке
            // возвращает частное в инвертированном порядке, остаток через out
            if (dividend.Length == 0)
            {
                remainder = 0;
                return [0];
            }

            Digit[] result = new Digit[dividend.Length];
            long running = 0;

            for (int i = dividend.Length - 1; i >= 0; i--)
            {
                running = running * basis_num_sys + dividend[i];
                long quotient = Math.DivRem(running, divisor, out long rem);
                result[i] = (Digit)quotient;
                running = rem;
            }

            remainder = (int)running;

            int last = result.Length - 1;
            while (last > 0 && result[last] == 0)
                last--;

            if (last == result.Length - 1)
                return result;

            Digit[] trimmed = new Digit[last + 1];
            Array.Copy(result, trimmed, trimmed.Length);
            return trimmed;
        }

    }
}
