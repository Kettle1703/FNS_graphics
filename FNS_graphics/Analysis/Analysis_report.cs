using System.Collections.Generic;

namespace FNS_rebuild
{
    internal sealed class Analysis_report
    {
        internal List<Performance_point> Points { get; } = [];
        internal Dictionary<char, long> Symbol_counts { get; } = [];
        internal long Total_ciphertext_symbols = 0;
        internal bool Include_avalanche_sheets = true;
        internal bool Include_interference_sheet = true;
    }
}
