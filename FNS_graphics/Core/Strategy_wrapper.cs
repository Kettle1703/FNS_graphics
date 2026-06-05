namespace FNS_rebuild
{
    internal class Strategy_wrapper
    {
        // Класс-обёртка, который хранит текущую стратегию и делегирует ей вызовы.
        private IStrategy strategy;

        internal Strategy_wrapper(IStrategy input_strategy)
        {
            strategy = input_strategy;
        }

        internal void Set_strategy(IStrategy input_strategy)
        {
            strategy = input_strategy;
        }

        internal string Encrypt(string input, Cipher_options options)
        {
            return strategy.Encrypt(input, options);
        }

        internal string Decrypt(string input, Cipher_options options)
        {
            return strategy.Decrypt(input, options);
        }
    }
}
