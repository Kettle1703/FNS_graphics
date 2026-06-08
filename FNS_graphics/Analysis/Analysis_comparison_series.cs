namespace FNS_rebuild
{
    internal sealed class Analysis_comparison_series
    {
        internal Analysis_comparison_series(string name, Analysis_report report)
        {
            Name = name;
            Report = report;
        }

        internal string Name { get; }
        internal Analysis_report Report { get; }
    }
}
