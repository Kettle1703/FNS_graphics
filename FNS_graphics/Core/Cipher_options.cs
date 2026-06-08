namespace FNS_rebuild
{
    internal class Cipher_options
    {
        // Класс хранит настройки шифрования для конкретного запуска Encrypt/Decrypt.

        internal int Block_plain_text_length = 0;  // Максимальная длина открытого блока; 0 означает шифрование без подблоков.
        internal string Key = "";  // Текстовый ключ; будет преобразован в коэффициенты ФСС и применён к коэффициентам сообщения.
        internal bool Enable_round_cipher = true;  // Управляет включением раундового слоя поверх ФСС-коэффициентов.
        internal Encryption_core_kind Encryption_core = Encryption_core_kind.Factorial;
        internal byte[]? Fixed_message_nonce = null;  // Служебно для анализа: фиксирует nonce/IV при парном сравнении шифротекстов.

        internal static readonly Cipher_options Default = new();  // Набор настроек по умолчанию: без блоков и без ключа.

        internal bool Use_blocks()
        {
            // Показывает, нужно ли включать блочное шифрование.

            return Block_plain_text_length > 0;
        }

        internal bool Use_key()
        {
            // Показывает, нужно ли применять ключ к коэффициентам ФСС.

            return Enable_round_cipher && !string.IsNullOrEmpty(Key);
        }
    }
}
