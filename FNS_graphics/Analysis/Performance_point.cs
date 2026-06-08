namespace FNS_rebuild
{
    internal sealed class Performance_point
    {
        internal int Source_length_symbols = 0;

        internal double Average_source_bytes = 0;
        internal double Average_ciphertext_bytes = 0;
        internal double Expansion_ratio = 0;
        internal double Absolute_growth_bytes = 0;

        internal double Average_encrypt_ms = 0;
        internal double Average_decrypt_ms = 0;
        internal double Encrypt_throughput_bytes_per_second = 0;
        internal double Decrypt_throughput_bytes_per_second = 0;

        internal double Message_avalanche_ratio = 0;
        internal double Key_sensitivity_ratio = 0;

        internal double Interference_recovery_ratio = 0;
        internal double Interference_detected_failure_ratio = 0;
        internal double Interference_undetected_damage_ratio = 0;
        internal double Interference_safe_outcome_ratio = 0;
    }
}
