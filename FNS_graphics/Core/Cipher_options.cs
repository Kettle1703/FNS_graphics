using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
namespace FNS_rebuild
{
    internal class Cipher_options
    {
        // Класс хранит настройки шифрования для конкретного запуска Encrypt/Decrypt.

        internal int Block_plain_text_length = 0;  // Максимальная длина открытого блока; 0 означает шифрование без подблоков.
        internal string Key = "";  // Текстовый ключ; будет преобразован в коэффициенты ФСС и применён к коэффициентам сообщения.

        internal static readonly Cipher_options Default = new();  // Набор настроек по умолчанию: без блоков и без ключа.

        internal bool Use_blocks()
        {
            // Показывает, нужно ли включать блочное шифрование.

            return Block_plain_text_length > 0;
        }

        internal bool Use_key()
        {
            // Показывает, нужно ли применять ключ к коэффициентам ФСС.

            return !string.IsNullOrEmpty(Key);
        }
    }
}
