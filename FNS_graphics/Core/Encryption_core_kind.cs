using System;

namespace FNS_rebuild
{
    internal enum Encryption_core_kind
    {
        Factorial = 0,
        KuznyechikCbc = 1,
        AesGcm = 2
    }

    internal static class Encryption_core_catalog
    {
        internal const string Factorial_id = "factorial";
        internal const string Kuznyechik_cbc_id = "kuznyechik-cbc-gost-r-34-12-2015";
        internal const string Aes_gcm_id = "aes-gcm-256";

        internal const string Factorial_display_name = "Факториальная система счисления";
        internal const string Kuznyechik_cbc_display_name = "Кузнечик-CBC (ГОСТ Р 34.12-2015 / ГОСТ Р 34.13-2015)";
        internal const string Aes_gcm_display_name = "AES-GCM-256";

        internal static string To_storage_id(Encryption_core_kind core)
        {
            return core switch
            {
                Encryption_core_kind.KuznyechikCbc => Kuznyechik_cbc_id,
                Encryption_core_kind.AesGcm => Aes_gcm_id,
                _ => Factorial_id
            };
        }

        internal static Encryption_core_kind From_storage_id(string? value)
        {
            string normalized = (value ?? string.Empty).Trim();
            if (string.Equals(normalized, Kuznyechik_cbc_id, StringComparison.OrdinalIgnoreCase))
                return Encryption_core_kind.KuznyechikCbc;

            if (string.Equals(normalized, Aes_gcm_id, StringComparison.OrdinalIgnoreCase))
                return Encryption_core_kind.AesGcm;

            return Encryption_core_kind.Factorial;
        }
    }
}
