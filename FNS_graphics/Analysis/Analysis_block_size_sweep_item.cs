namespace FNS_rebuild
{
    internal sealed class Analysis_block_size_sweep_item
    {
        internal Analysis_block_size_sweep_item(int block_plain_text_length, Analysis_report report)
        {
            Block_plain_text_length = block_plain_text_length;
            Report = report;
        }

        internal int Block_plain_text_length { get; }
        internal Analysis_report Report { get; }
    }
}
