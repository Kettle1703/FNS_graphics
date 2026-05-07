using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
using System.Numerics;

namespace FNS_rebuild
{
    class Stochastic_tests_long_math
    {
        static readonly Random random = new(); // общий генератор случайных значений
        const int Default_iterations = 1000; // число прогонов по умолчанию
        const int Min_base = 256; // диапазон оснований системы счисления для тестов
        const int Max_base = 256; // верхняя граница основания системы счисления
        const int Min_digits = 1; // диапазон длины чисел в разрядах
        const int Max_digits = 2000; // верхняя граница длины чисел в разрядах
        const int Max_print = 500; // лимит вывода первых ошибок в консоль
        const int Example_print = 13; // количество примеров для вывода в консоль

        delegate Digit[] Function(Digit[] left, Digit[] right);

        sealed class Binary_op_test
        {
            internal string Name { get; }
            internal Function Actual { get; }
            internal Func<BigInteger, BigInteger, BigInteger> Expected { get; }

            internal Binary_op_test(
                string name,
                Function actual,
                Func<BigInteger, BigInteger, BigInteger> expected)
            {
                Name = name;
                Actual = actual;
                Expected = expected;
            }
        }

        static readonly Binary_op_test[] Binary_ops = // список тестируемых бинарных операций
        [
            new Binary_op_test("Summa", Long_math.Summa, BigInteger.Add),
            new Binary_op_test("Multiply", Long_math.Multiply, BigInteger.Multiply),
            new Binary_op_test("Difference", Long_math.Difference, (a, b) => a < b ? a : a - b),
            new Binary_op_test("Divide", (a, b) => { Digit[] q; Long_math.Divide(a, b, out q); return q; }, (a, b) => b == 0 ? a : a < b ? a : a / b)
        ];

        internal static int Run_all()
        {
            // Запускает все стохастические тесты, зарегистрированные в списках.
            return Run_binary_op_tests(Binary_ops, Default_iterations);
        }

        internal static int Run_binary_op_tests(int iterations)
        {
            // Запускает стохастические тесты бинарных операций с заданным числом прогонов.
            return Run_binary_op_tests(Binary_ops, iterations);
        }

        static int Run_binary_op_tests(Binary_op_test[] tests, int iterations)
        {
            // Запускает набор бинарных тестов для операций вида Digit[] x Digit[] -> Digit[].
            if (tests == null || tests.Length == 0 || iterations <= 0)
                return 0;

            int failures = 0;
            foreach (Binary_op_test test in tests)
                failures += Run_binary_op_test(test, iterations);

            return failures;
        }

        static int Run_binary_op_test(Binary_op_test test, int iterations)
        {
            // Выполняет стохастическую проверку одного бинарного делегата.
            int failures = 0;
            int printed = 0;
            int examples_printed = 0;

            for (int i = 0; i < iterations; i++)
            {
                int base_value = random.Next(Min_base, Max_base + 1);

                Digit[] a = Generate_random_digits(base_value, Min_digits, Max_digits);
                Digit[] b = Generate_random_digits(base_value, Min_digits, Max_digits);

                BigInteger a_value = Convert_to_BigInteger(a, base_value);
                BigInteger b_value = Convert_to_BigInteger(b, base_value);

                Digit[] actual_digits = test.Actual(a, b);
                BigInteger actual = Convert_to_BigInteger(actual_digits, base_value);
                BigInteger expected = test.Expected(a_value, b_value);

                if (Analysis.debug_mode && examples_printed < Example_print)
                {
                    Print_example(test, base_value, a, b, actual_digits, a_value, b_value, actual, expected);
                    examples_printed++;
                }

                if (actual != expected)
                {
                    failures++;
                    if (printed < Max_print)
                    {
                        WriteLine($"{test.Name} fail: base={base_value} a={a_value} b={b_value} expected={expected} actual={actual}");
                        WriteLine("a (digits):");
                        Analysis.Print(a);
                        WriteLine("b (digits):");
                        Analysis.Print(b);
                        WriteLine("result (digits):");
                        Analysis.Print(actual_digits);
                        printed++;
                    }
                }
            }

            int passed = iterations - failures;
            WriteLine($"{test.Name}: {passed}/{iterations} passed");
            return failures;
        }

        static Digit[] Generate_random_digits(int base_value, int minDigits, int maxDigits)
        {
            // Генерирует массив случайных разрядов (младший разряд первым).
            int length = random.Next(minDigits, maxDigits + 1);
            Digit[] digits = new Digit[length];
            for (int i = 0; i < length; i++)
                digits[i] = (Digit)random.Next(0, base_value);

            if (length > 1 && digits[length - 1] == 0)
                digits[length - 1] = (Digit)random.Next(1, base_value);

            return digits;
        }

        static BigInteger Convert_to_BigInteger(Digit[] digits, int base_value)
        {
            // Преобразует массив разрядов (младший разряд первым) в BigInteger.
            BigInteger value = BigInteger.Zero;
            BigInteger factor = BigInteger.One;

            for (int i = 0; i < digits.Length; i++)
            {
                value += digits[i] * factor;
                factor *= base_value;
            }

            return value;
        }

        static void Print_example(
            Binary_op_test test,
            int base_value,
            Digit[] a,
            Digit[] b,
            Digit[] result_digits,
            BigInteger a_value,
            BigInteger b_value,
            BigInteger actual,
            BigInteger expected)
        {
            // Печатает один пример для ручной проверки.
            WriteLine($"{test.Name} example:");
            WriteLine($"base = {base_value}");
            WriteLine("a (digits):");
            Analysis.Print(a);
            WriteLine("b (digits):");
            Analysis.Print(b);
            WriteLine("result (digits):");
            Analysis.Print(result_digits);
            WriteLine($"a (dec) = {a_value} (len={a.Length})");
            WriteLine($"b (dec) = {b_value} (len={b.Length})");
            WriteLine($"result (dec)   = {actual} (len={result_digits.Length})");
            WriteLine($"expected (dec) = {expected}");
            WriteLine();
        }
    }
}
