namespace FNS_rebuild
{
    internal interface IStrategy
    {
        // Переводит исходную строку в шифротекст с заданными настройками.
        string Encrypt(string input, Cipher_options options);

        // Переводит шифротекст в исходную строку с заданными настройками.
        string Decrypt(string input, Cipher_options options);
    }
}
