using System;
using System.Collections.Generic;
using System.IO;
using OfficeOpenXml;

namespace FNS_rebuild
{
    internal static class Analysis_excel_report_writer
    {
        internal static void Save(Analysis_report report, string output_xlsx_path)
        {
            string? directory = Path.GetDirectoryName(output_xlsx_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            FileInfo file = new(output_xlsx_path);
            if (file.Exists)
                file.Delete();

            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

            using ExcelPackage package = new(file);

            Fill_expansion_sheet(package.Workbook.Worksheets.Add("Коэф_увеличения"), report.Points);
            Fill_absolute_growth_sheet(package.Workbook.Worksheets.Add("Абс_прирост"), report.Points);
            Fill_single_metric_sheet(
                package.Workbook.Worksheets.Add("Время_шифрования"),
                report.Points,
                "Среднее время шифрования, мс",
                point => point.Average_encrypt_ms,
                "0.000000");
            Fill_single_metric_sheet(
                package.Workbook.Worksheets.Add("Время_дешифрования"),
                report.Points,
                "Среднее время дешифрования, мс",
                point => point.Average_decrypt_ms,
                "0.000000");
            Fill_single_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_шифрование"),
                report.Points,
                "Пропускная способность шифрования, байт/с",
                point => point.Encrypt_throughput_bytes_per_second,
                "0.000");
            Fill_single_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_дешифр"),
                report.Points,
                "Пропускная способность дешифрования, байт/с",
                point => point.Decrypt_throughput_bytes_per_second,
                "0.000");

            if (report.Include_avalanche_sheets)
            {
                Fill_single_metric_sheet(
                    package.Workbook.Worksheets.Add("Лавина_сообщение"),
                    report.Points,
                    "Средняя доля отличий шифротекстов (изменение 1 символа сообщения)",
                    point => point.Message_avalanche_ratio,
                    "0.000000");
                Fill_single_metric_sheet(
                    package.Workbook.Worksheets.Add("Чувствительность_ключа"),
                    report.Points,
                    "Средняя доля отличий шифротекстов (изменение 1 символа ключа)",
                    point => point.Key_sensitivity_ratio,
                    "0.000000");
            }

            if (report.Include_interference_sheet)
                Fill_interference_sheet(package.Workbook.Worksheets.Add("Помехоустойчивость"), report.Points);

            Fill_distribution_sheet(
                package.Workbook.Worksheets.Add("Распределение"),
                report.Symbol_counts,
                report.Total_ciphertext_symbols);

            package.Save();
        }

        static void Fill_expansion_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";
            sheet.Cells[1, 2].Value = "Средняя длина исходной строки, байт UTF-8";
            sheet.Cells[1, 3].Value = "Средняя длина шифротекста, байт UTF-8";
            sheet.Cells[1, 4].Value = "Коэффициент увеличения по байтам";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length_symbols;
                sheet.Cells[row, 2].Value = point.Average_source_bytes;
                sheet.Cells[row, 3].Value = point.Average_ciphertext_bytes;
                sheet.Cells[row, 4].Value = point.Expansion_ratio;
                row++;
            }

            Format_range(sheet, row, 2, "0.000");
            Format_range(sheet, row, 3, "0.000");
            Format_range(sheet, row, 4, "0.000000");
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_absolute_growth_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";
            sheet.Cells[1, 2].Value = "Абсолютный прирост |C|-|M|, байт UTF-8";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length_symbols;
                sheet.Cells[row, 2].Value = point.Absolute_growth_bytes;
                row++;
            }

            Format_range(sheet, row, 2, "0.000");
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_single_metric_sheet(
            ExcelWorksheet sheet,
            List<Performance_point> points,
            string value_header,
            Func<Performance_point, double> value_selector,
            string number_format)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";
            sheet.Cells[1, 2].Value = value_header;

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length_symbols;
                sheet.Cells[row, 2].Value = value_selector(point);
                row++;
            }

            Format_range(sheet, row, 2, number_format);
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_interference_sheet(ExcelWorksheet sheet, List<Performance_point> points)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";
            sheet.Cells[1, 2].Value = "Доля восстановленных JSON-пакетов";
            sheet.Cells[1, 3].Value = "Доля обнаруженных невосстановленных ошибок";
            sheet.Cells[1, 4].Value = "Доля необнаруженных повреждений";

            int row = 2;
            foreach (Performance_point point in points)
            {
                sheet.Cells[row, 1].Value = point.Source_length_symbols;
                sheet.Cells[row, 2].Value = point.Interference_recovery_ratio;
                sheet.Cells[row, 3].Value = point.Interference_detected_failure_ratio;
                sheet.Cells[row, 4].Value = point.Interference_undetected_damage_ratio;
                row++;
            }

            Format_range(sheet, row, 2, "0.000000");
            Format_range(sheet, row, 3, "0.000000");
            Format_range(sheet, row, 4, "0.000000");
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

            sheet.Cells[1, 6].Value = "Всего символов";
            sheet.Cells[1, 7].Value = total_ciphertext_symbols;
            sheet.Cells[2, 6].Value = "Энтропия (бит/символ)";
            sheet.Cells[2, 7].Value = Compute_entropy(symbol_counts, total_ciphertext_symbols);

            Format_range(sheet, row, 4, "0.000000");
            sheet.Cells[2, 7].Style.Numberformat.Format = "0.000000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Format_range(ExcelWorksheet sheet, int next_row, int column, string format)
        {
            if (next_row <= 2)
                return;

            sheet.Cells[2, column, next_row - 1, column].Style.Numberformat.Format = format;
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
    }
}
