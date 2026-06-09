using System;
using System.IO;

namespace FNS_rebuild
{
    internal enum Analysis_report_kind
    {
        All,
        Fss_block_length,
        Fss_round_cipher,
        Fss_block_round_matrix,
        Fss_block_size_sweep,
        Encryption_core
    }

    internal sealed class Analysis_report_batch_options
    {
        internal Analysis_report_kind Report_kind = Analysis_report_kind.All;
        internal string Output_dir = Path.Combine(AppContext.BaseDirectory, "analysis_reports");
        internal int Min_length = 1;
        internal int Max_length = 5000;
        internal int Length_step = 1;
        internal int Tests_per_length = 3;
        internal int Avalanche_tests_per_length = 3;
        internal int Interference_tests_per_length = 3;
        internal int Progress_step = 250;
        internal bool Include_avalanche_sheet = true;
        internal bool Include_interference_sheet = true;
        internal bool Use_high_process_priority = false;

        internal Performance_report_options Build_performance_options(string output_path)
        {
            return new Performance_report_options
            {
                Min_length = Min_length,
                Max_length = Max_length,
                Length_step = Length_step,
                Tests_per_length = Tests_per_length,
                Avalanche_tests_per_length = Avalanche_tests_per_length,
                Interference_tests_per_length = Interference_tests_per_length,
                Progress_step = Progress_step,
                Output_xlsx_path = output_path,
                Include_avalanche_sheet = Include_avalanche_sheet,
                Include_interference_sheet = Include_interference_sheet
            };
        }

        internal void Validate()
        {
            Build_performance_options(Path.Combine(Output_dir, "validation.xlsx")).Validate();

            if (string.IsNullOrWhiteSpace(Output_dir))
                throw new ArgumentException("Нужно указать папку для выходных xlsx-файлов.", nameof(Output_dir));
        }
    }
}
