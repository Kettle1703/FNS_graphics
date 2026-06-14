using System;
using System.Collections.Generic;
using OfficeOpenXml;
using OfficeOpenXml.Drawing.Chart;

namespace FNS_rebuild
{
    internal static class Analysis_block_size_sweep_excel_writer
    {
        const double Bytes_per_kilobyte = 1024.0;

        internal static void Save(
            IReadOnlyList<Analysis_block_size_sweep_item> items,
            Performance_report_options options,
            string output_xlsx_path)
        {
            if (items.Count == 0)
                throw new ArgumentException("Нужно передать хотя бы один размер блока.", nameof(items));

            using ExcelPackage package = Analysis_excel_package.Create_new(output_xlsx_path);

            Fill_parameters_sheet(package.Workbook.Worksheets.Add("Параметры"), items, options);
            Fill_summary_sheet(package.Workbook.Worksheets.Add("Сводка"), items);
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Коэф_увеличения"),
                items,
                "Средний коэффициент увеличения по байтам",
                point => point.Expansion_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Абс_прирост"),
                items,
                "Средний абсолютный прирост размера, байт",
                point => point.Absolute_growth_bytes,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Время_шифрования"),
                items,
                "Среднее время шифрования, мс",
                point => point.Average_encrypt_ms,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Время_дешифрования"),
                items,
                "Среднее время дешифрования, мс",
                point => point.Average_decrypt_ms,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_шифрование"),
                items,
                "Средняя пропускная способность шифрования, КБ/с",
                point => point.Encrypt_throughput_bytes_per_second / Bytes_per_kilobyte,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_дешифр"),
                items,
                "Средняя пропускная способность дешифрования, КБ/с",
                point => point.Decrypt_throughput_bytes_per_second / Bytes_per_kilobyte,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Лавина_сообщение"),
                items,
                "Средний лавинный эффект сообщения",
                point => point.Message_avalanche_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Чувствительность_ключа"),
                items,
                "Средняя чувствительность к ключу",
                point => point.Key_sensitivity_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Помехоустойчивость"),
                items,
                "Средняя доля восстановленных или обнаруженных повреждений",
                point => point.Interference_safe_outcome_ratio,
                "0.000000");

            package.Save();
        }

        static void Fill_parameters_sheet(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_block_size_sweep_item> items,
            Performance_report_options options)
        {
            sheet.Cells[1, 1].Value = "Параметр";
            sheet.Cells[1, 2].Value = "Значение";
            sheet.Cells[2, 1].Value = "Диапазон длин сообщений";
            sheet.Cells[2, 2].Value = $"{options.Min_length}..{options.Max_length}";
            sheet.Cells[3, 1].Value = "Шаг длины сообщений";
            sheet.Cells[3, 2].Value = options.Length_step;
            sheet.Cells[4, 1].Value = "Повторов Encrypt/Decrypt на длину";
            sheet.Cells[4, 2].Value = options.Tests_per_length;
            sheet.Cells[5, 1].Value = "Парных тестов лавины/ключа на длину";
            sheet.Cells[5, 2].Value = options.Avalanche_tests_per_length;
            sheet.Cells[6, 1].Value = "Тестов помехоустойчивости на длину";
            sheet.Cells[6, 2].Value = options.Interference_tests_per_length;
            sheet.Cells[7, 1].Value = "Раундовое шифрование";
            sheet.Cells[7, 2].Value = "включено";
            sheet.Cells[9, 1].Value = "Размеры блоков";

            for (int i = 0; i < items.Count; i++)
                sheet.Cells[10 + i, 1].Value = items[i].Block_plain_text_length;

            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_summary_sheet(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_block_size_sweep_item> items)
        {
            string[] headers =
            [
                "Размер блока",
                "Коэф. увеличения",
                "Абс. прирост, байт",
                "Время шифрования, мс",
                "Время дешифрования, мс",
                "Пропуск шифрования, КБ/с",
                "Пропуск дешифрования, КБ/с",
                "Лавина сообщения",
                "Чувствительность к ключу",
                "Помехоустойчивость"
            ];

            for (int i = 0; i < headers.Length; i++)
                sheet.Cells[1, i + 1].Value = headers[i];

            for (int i = 0; i < items.Count; i++)
            {
                int row = i + 2;
                Analysis_report report = items[i].Report;
                sheet.Cells[row, 1].Value = items[i].Block_plain_text_length;
                sheet.Cells[row, 2].Value = Average(report, point => point.Expansion_ratio);
                sheet.Cells[row, 3].Value = Average(report, point => point.Absolute_growth_bytes);
                sheet.Cells[row, 4].Value = Average(report, point => point.Average_encrypt_ms);
                sheet.Cells[row, 5].Value = Average(report, point => point.Average_decrypt_ms);
                sheet.Cells[row, 6].Value = Average(report, point => point.Encrypt_throughput_bytes_per_second) / Bytes_per_kilobyte;
                sheet.Cells[row, 7].Value = Average(report, point => point.Decrypt_throughput_bytes_per_second) / Bytes_per_kilobyte;
                sheet.Cells[row, 8].Value = Average(report, point => point.Message_avalanche_ratio);
                sheet.Cells[row, 9].Value = Average(report, point => point.Key_sensitivity_ratio);
                sheet.Cells[row, 10].Value = Average(report, point => point.Interference_safe_outcome_ratio);
            }

            if (items.Count > 0)
                sheet.Cells[2, 2, items.Count + 1, 10].Style.Numberformat.Format = "0.000000";

            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static void Fill_metric_sheet(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_block_size_sweep_item> items,
            string metric_header,
            Func<Performance_point, double> selector,
            string number_format)
        {
            sheet.Cells[1, 1].Value = "Размер блока, символов";
            sheet.Cells[1, 2].Value = metric_header;

            for (int i = 0; i < items.Count; i++)
            {
                int row = i + 2;
                sheet.Cells[row, 1].Value = items[i].Block_plain_text_length;
                sheet.Cells[row, 2].Value = Average(items[i].Report, selector);
            }

            if (items.Count > 0)
                sheet.Cells[2, 2, items.Count + 1, 2].Style.Numberformat.Format = number_format;

            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
            Add_line_chart(sheet, items.Count, metric_header);
        }

        static void Add_line_chart(ExcelWorksheet sheet, int row_count, string metric_header)
        {
            if (row_count <= 0)
                return;

            ExcelLineChart chart = sheet.Drawings.AddLineChart(
                $"chart_{Guid.NewGuid():N}",
                eLineChartType.LineMarkers);
            chart.Title.Text = metric_header;
            chart.SetPosition(1, 0, 4, 0);
            chart.SetSize(860, 420);
            chart.XAxis.Title.Text = "Размер блока, символов";
            chart.YAxis.Title.Text = metric_header;
            chart.Legend.Remove();
            chart.Series.Add(sheet.Cells[2, 2, row_count + 1, 2], sheet.Cells[2, 1, row_count + 1, 1]);
        }

        static double Average(Analysis_report report, Func<Performance_point, double> selector)
        {
            if (report.Points.Count == 0)
                return 0.0;

            double sum = 0.0;
            foreach (Performance_point point in report.Points)
                sum += selector(point);

            return sum / report.Points.Count;
        }
    }
}
