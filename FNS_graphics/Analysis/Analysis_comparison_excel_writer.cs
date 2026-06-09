using System;
using System.Collections.Generic;
using System.IO;
using OfficeOpenXml;
using OfficeOpenXml.Drawing.Chart;

namespace FNS_rebuild
{
    internal static class Analysis_comparison_excel_writer
    {
        const double Bytes_per_kilobyte = 1024.0;

        internal static void Save(
            IReadOnlyList<Analysis_comparison_series> series,
            string output_xlsx_path)
        {
            if (series.Count == 0)
                throw new ArgumentException("Нужно передать хотя бы одну серию сравнения.", nameof(series));

            string? directory = Path.GetDirectoryName(output_xlsx_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            FileInfo file = new(output_xlsx_path);
            if (file.Exists)
                file.Delete();

            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
            using ExcelPackage package = new(file);

            Fill_source_size_sheet(package.Workbook.Worksheets.Add("Служебные_размеры"), series);

            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Коэф_увеличения"),
                series,
                "Коэффициент увеличения по байтам",
                point => point.Expansion_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Абс_прирост"),
                series,
                "Абсолютный прирост размера, байт",
                point => point.Absolute_growth_bytes,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Время_шифрования"),
                series,
                "Среднее время шифрования, мс",
                point => point.Average_encrypt_ms,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Время_дешифрования"),
                series,
                "Среднее время дешифрования, мс",
                point => point.Average_decrypt_ms,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_шифрование"),
                series,
                "Пропускная способность шифрования, КБ/с",
                point => point.Encrypt_throughput_bytes_per_second / Bytes_per_kilobyte,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Пропуск_дешифр"),
                series,
                "Пропускная способность дешифрования, КБ/с",
                point => point.Decrypt_throughput_bytes_per_second / Bytes_per_kilobyte,
                "0.000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Лавина_сообщение"),
                series,
                "Лавинный эффект сообщения",
                point => point.Message_avalanche_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Чувствительность_ключа"),
                series,
                "Чувствительность к ключу",
                point => point.Key_sensitivity_ratio,
                "0.000000");
            Fill_metric_sheet(
                package.Workbook.Worksheets.Add("Помехоустойчивость"),
                series,
                "Доля восстановленных или обнаруженных повреждений",
                point => point.Interference_safe_outcome_ratio,
                "0.000000");
            package.Save();
        }

        static void Fill_metric_sheet(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_comparison_series> series,
            string metric_header,
            Func<Performance_point, double> selector,
            string number_format)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";
            for (int series_index = 0; series_index < series.Count; series_index++)
                sheet.Cells[1, series_index + 2].Value = series[series_index].Name;

            List<int> lengths = Build_length_axis(series);
            for (int row_index = 0; row_index < lengths.Count; row_index++)
            {
                int row = row_index + 2;
                int length = lengths[row_index];
                sheet.Cells[row, 1].Value = length;

                for (int series_index = 0; series_index < series.Count; series_index++)
                {
                    if (Try_find_point(series[series_index].Report, length, out Performance_point point))
                        sheet.Cells[row, series_index + 2].Value = selector(point);
                }
            }

            sheet.Cells[1, series.Count + 3].Value = "Показатель";
            sheet.Cells[2, series.Count + 3].Value = metric_header;
            if (lengths.Count > 0)
                sheet.Cells[2, 2, lengths.Count + 1, series.Count + 1].Style.Numberformat.Format = number_format;
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();

            Add_draft_line_chart(sheet, series, lengths.Count, metric_header);
        }

        static void Add_draft_line_chart(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_comparison_series> series,
            int row_count,
            string metric_header)
        {
            if (row_count <= 0 || series.Count == 0)
                return;

            ExcelLineChart chart = sheet.Drawings.AddLineChart(
                $"chart_{Guid.NewGuid():N}",
                eLineChartType.Line);
            chart.Title.Text = metric_header;
            chart.SetPosition(1, 0, series.Count + 4, 0);
            chart.SetSize(900, 420);
            chart.XAxis.Title.Text = "Длина исходной строки, символов";
            chart.YAxis.Title.Text = metric_header;
            chart.Legend.Position = eLegendPosition.Bottom;

            ExcelRange x_axis = sheet.Cells[2, 1, row_count + 1, 1];
            for (int series_index = 0; series_index < series.Count; series_index++)
            {
                ExcelRange values = sheet.Cells[2, series_index + 2, row_count + 1, series_index + 2];
                ExcelChartSerie chart_series = chart.Series.Add(values, x_axis);
                chart_series.Header = series[series_index].Name;
            }
        }

        static void Fill_source_size_sheet(
            ExcelWorksheet sheet,
            IReadOnlyList<Analysis_comparison_series> series)
        {
            sheet.Cells[1, 1].Value = "Длина исходной строки, символов";

            int column = 2;
            foreach (Analysis_comparison_series item in series)
            {
                sheet.Cells[1, column].Value = $"{item.Name}: средняя длина исходной строки, байт UTF-8";
                sheet.Cells[1, column + 1].Value = $"{item.Name}: средняя длина шифротекста, байт UTF-8";
                column += 2;
            }

            List<int> lengths = Build_length_axis(series);
            for (int row_index = 0; row_index < lengths.Count; row_index++)
            {
                int row = row_index + 2;
                int length = lengths[row_index];
                sheet.Cells[row, 1].Value = length;

                column = 2;
                foreach (Analysis_comparison_series item in series)
                {
                    if (Try_find_point(item.Report, length, out Performance_point point))
                    {
                        sheet.Cells[row, column].Value = point.Average_source_bytes;
                        sheet.Cells[row, column + 1].Value = point.Average_ciphertext_bytes;
                    }

                    column += 2;
                }
            }

            if (lengths.Count > 0)
                sheet.Cells[2, 2, lengths.Count + 1, column - 1].Style.Numberformat.Format = "0.000";
            sheet.Cells[sheet.Dimension.Address].AutoFitColumns();
        }

        static List<int> Build_length_axis(IReadOnlyList<Analysis_comparison_series> series)
        {
            SortedSet<int> lengths = [];
            foreach (Analysis_comparison_series item in series)
            {
                foreach (Performance_point point in item.Report.Points)
                    lengths.Add(point.Source_length_symbols);
            }

            return [.. lengths];
        }

        static bool Try_find_point(Analysis_report report, int length, out Performance_point result)
        {
            foreach (Performance_point point in report.Points)
            {
                if (point.Source_length_symbols == length)
                {
                    result = point;
                    return true;
                }
            }

            result = null!;
            return false;
        }
    }
}
