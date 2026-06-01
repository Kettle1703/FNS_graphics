using System;
using System.Text;

namespace FNS_rebuild
{
    internal static class Base64_url_codec
    {
        // Кодирует байты в Base64URL без padding-символов '='.
        internal static string Encode(byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            string base64 = Convert.ToBase64String(bytes);
            return base64
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        // Декодирует строку в байты. Принимает Base64 и Base64URL (с padding и без).
        internal static bool Try_decode(string? encoded, out byte[] bytes)
        {
            bytes = [];
            string normalized = Normalize_text(encoded);
            if (normalized.Length == 0)
                return false;

            string standard = normalized.Replace('-', '+').Replace('_', '/');
            int remainder = standard.Length % 4;
            if (remainder == 1)
                return false;
            if (remainder == 2)
                standard += "==";
            else if (remainder == 3)
                standard += "=";

            int buffer_length = ((standard.Length + 3) / 4) * 3;
            byte[] buffer = new byte[buffer_length];
            if (!Convert.TryFromBase64String(standard, buffer, out int written))
                return false;

            bytes = new byte[written];
            Array.Copy(buffer, bytes, written);
            return true;
        }

        // Приводит Base64/Base64URL к каноничному виду Base64URL без '='.
        // Если вход не похож на Base64, возвращает только очищенный текст.
        internal static string Canonicalize_if_possible(string? encoded)
        {
            string normalized = Normalize_text(encoded);
            if (normalized.Length == 0)
                return string.Empty;

            if (!Try_decode(normalized, out byte[] bytes))
                return normalized;

            return Encode(bytes);
        }

        internal static string Normalize_text(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string source = value.Trim();
            StringBuilder builder = new(source.Length);
            foreach (char ch in source)
            {
                if (!char.IsWhiteSpace(ch))
                    builder.Append(ch);
            }

            return builder.ToString();
        }
    }
}
