using System;
using FNS_graphics;

namespace FNS_rebuild
{
    internal sealed class Performance_report_options
    {
        // Диапазон длин исходной строки в символах. Это ось X для всех листов.
        public int Min_length = 1;
        public int Max_length = 5000;
        public int Length_step = 1;

        // Количество прогонов Encrypt/Decrypt для каждой длины.
        public int Tests_per_length = 3;

        // Количество парных тестов лавинного эффекта и чувствительности к ключу.
        public int Avalanche_tests_per_length = 3;

        // Количество тестов повреждения JSON-пакета для каждой длины.
        public int Interference_tests_per_length = 3;

        // Шаг вывода прогресса в консоль.
        public int Progress_step = 250;

        // Путь до одного итогового xlsx-файла.
        public string Output_xlsx_path = App_storage_paths.Analysis_report_file_path;

        // Включать ли листы лавинного теста и чувствительности к ключу.
        public bool Include_avalanche_sheet = true;

        // Включать ли лист помехоустойчивости передачи.
        public bool Include_interference_sheet = true;

        internal void Validate()
        {
            if (Min_length < 1)
                throw new ArgumentOutOfRangeException(nameof(Min_length), "Минимальная длина должна быть >= 1.");

            if (Max_length < Min_length)
                throw new ArgumentOutOfRangeException(nameof(Max_length), "Максимальная длина должна быть >= минимальной.");

            if (Length_step < 1)
                throw new ArgumentOutOfRangeException(nameof(Length_step), "Шаг длины должен быть >= 1.");

            if (Tests_per_length < 1)
                throw new ArgumentOutOfRangeException(nameof(Tests_per_length), "Тестов на длину должно быть >= 1.");

            if (Avalanche_tests_per_length < 1)
                throw new ArgumentOutOfRangeException(nameof(Avalanche_tests_per_length), "Лавинных тестов на длину должно быть >= 1.");

            if (Interference_tests_per_length < 1)
                throw new ArgumentOutOfRangeException(nameof(Interference_tests_per_length), "Тестов помехоустойчивости на длину должно быть >= 1.");

            if (Progress_step < 1)
                throw new ArgumentOutOfRangeException(nameof(Progress_step), "Шаг прогресса должен быть >= 1.");

            if (string.IsNullOrWhiteSpace(Output_xlsx_path))
                throw new ArgumentException("Нужно указать путь для выходного xlsx-файла.", nameof(Output_xlsx_path));
        }
    }
}
