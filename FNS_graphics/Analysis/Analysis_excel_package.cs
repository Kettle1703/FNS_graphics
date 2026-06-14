using System.IO;
using OfficeOpenXml;

namespace FNS_rebuild
{
    internal static class Analysis_excel_package
    {
        internal static ExcelPackage Create_new(string output_xlsx_path)
        {
            // Создаёт новый xlsx-файл: папка создаётся, старый файл удаляется.
            string? directory = Path.GetDirectoryName(output_xlsx_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            FileInfo file = new(output_xlsx_path);
            if (file.Exists)
                file.Delete();

            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
            return new ExcelPackage(file);
        }
    }
}
