using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
using System.Security.Cryptography;
using System.Text;

namespace FNS_rebuild
{
    internal sealed class Hybrid_cipher_package
    {
        // Поля пакета гибридного шифрования, который передаётся получателю.
        //
        // Ciphertext:
        // ФСС-шифротекст (после раундов вашего симметричного алгоритма).
        //
        // Encrypted_symmetric_key:
        // Открытый служебный материал для восстановления симметрического слоя ФСС.
        // Сейчас это HKDF salt; seed ФСС обе стороны выводят из ECDH shared secret + salt.
        //
        // Ephemeral_public_key:
        // Публичный ключ временной (ephemeral) ECC-пары отправителя в формате SPKI, Base64.
        // Нужен получателю, чтобы вычислить тот же shared secret и восстановить master key.
        //
        // Ephemeral_public_key_signature:
        // Цифровая подпись всего передаваемого пакета:
        // (Ciphertext + Encrypted_symmetric_key + Ephemeral_public_key + служебные параметры).
        // Формат: Base64, подпись ECDSA (DER), хеш SHA-256.
        //
        // Sender_signing_key_fingerprint:
        // Идентификатор ключа подписи отправителя (SHA-256 отпечаток SPKI-ключа, HEX).
        // Нужен получателю, чтобы быстро выбрать связанную тройку ключей.
        //
        // Block_plain_text_length:
        // Длина открытого блока ФСС. По ней восстанавливается режим разбиения на блоки.
        //
        // Curve_id:
        // Идентификатор эллиптической кривой для совместимости форматов.
        public string Ciphertext { get; set; } = "";
        public string Encrypted_symmetric_key { get; set; } = "";
        public string Ephemeral_public_key { get; set; } = "";
        public string Ephemeral_public_key_signature { get; set; } = "";
        public string Sender_signing_key_fingerprint { get; set; } = "";
        public int Block_plain_text_length { get; set; } = 0;
        public bool Round_cipher_enabled { get; set; } = true;
        public byte Curve_id { get; set; } = Hybrid_fns_cryptosystem.Curve_id_nist_p256;
    }

    internal sealed class Hybrid_sender_context : IDisposable
    {
        // Контекст отправителя для режима без автогенерации.
        // Позволяет переиспользовать одну и ту же ephemeral-пару и HKDF salt.
        internal ECDiffieHellman Sender_private_key { get; }
        internal byte[] Kdf_salt { get; }

        internal Hybrid_sender_context(ECDiffieHellman sender_private_key, byte[] kdf_salt)
        {
            Sender_private_key = sender_private_key ?? throw new ArgumentNullException(nameof(sender_private_key));
            Kdf_salt = kdf_salt ?? throw new ArgumentNullException(nameof(kdf_salt));
        }

        public void Dispose()
        {
            Sender_private_key.Dispose();
        }
    }

    internal sealed class Hybrid_fns_cryptosystem
    {
        // Гибридный слой: ECDH -> HKDF-SHA256 -> master key -> подключи -> ФСС-шифрование.
        // ФСС-ядро не меняется: этот класс только автоматически генерирует симметрические данные и вызывает Strategy_wrapper.
        //
        // Важно:
        // master key НЕ хранится как поле класса и НЕ должен быть статическим секретом.
        // Он вычисляется заново для каждого сообщения из текущего shared secret + salt.
        // Это обеспечивает уникальность ключевого материала на пакет.

        internal const int Master_key_bytes = 32; // 256 бит
        internal const byte Curve_id_nist_p256 = 1;

        const int Derived_fss_key_symbols = 256;
        const int Kdf_salt_bytes = 32;
        const int Fss_seed_bytes = 32;

        // Метки (domain separation labels) для HKDF/HMAC.
        // Нужны, чтобы разные этапы вывода ключей не пересекались по назначению.
        const string Master_key_info_label = "FNS_REBUILD_HYBRID_MASTER_KEY_V1";
        const string Fss_seed_info_label = "FNS_REBUILD_HYBRID_FSS_SEED_V1";
        const string Subkey_stream_label = "FNS_REBUILD_SUBKEY_STREAM_V1";
        const string Alphabet_permutation_info_label = "FNS_REBUILD_HYBRID_ALPHABET_PERMUTATION_V1";
        const string Alphabet_shuffle_stream_label = "FNS_REBUILD_ALPHABET_SHUFFLE_STREAM_V1";

        readonly string base_alphabet;

        internal Hybrid_fns_cryptosystem(Strategy_wrapper wrapper)
        {
            ArgumentNullException.ThrowIfNull(wrapper);
            if (string.IsNullOrEmpty(Factorial_strategy.alphabet))
                throw new InvalidOperationException("Базовый алфавит ФСС не инициализирован.");

            base_alphabet = Factorial_strategy.alphabet;
        }

        internal Hybrid_sender_context Create_sender_context()
        {
            ECDiffieHellman sender_private_key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] kdf_salt = RandomNumberGenerator.GetBytes(Kdf_salt_bytes);
            return new Hybrid_sender_context(sender_private_key, kdf_salt);
        }

        internal Hybrid_cipher_package Encrypt(
            string source,
            byte[] receiver_public_key_spki,
            Cipher_options? options = null,
            Hybrid_sender_context? sender_context = null)
        {
            // Шифрование гибридной схемой.
            // На выходе формируется пакет, содержащий:
            // - сам ФСС-шифротекст;
            // - служебный материал восстановления симметрического слоя;
            // - ephemeral публичный ключ.
            options ??= Cipher_options.Default;

            // Ephemeral-static ECDH:
            // 1) отправитель использует либо временную пару на один пакет,
            //    либо переданный фиксированный контекст отправителя;
            // 2) использует публичный ключ получателя;
            // 3) получает shared secret для текущей операции.
            ECDiffieHellman? local_sender_ephemeral = null;
            ECDiffieHellman sender_ephemeral = sender_context is null
                ? local_sender_ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)
                : sender_context.Sender_private_key;

            try
            {
                using ECDiffieHellman receiver_public_holder = ECDiffieHellman.Create();
                receiver_public_holder.ImportSubjectPublicKeyInfo(receiver_public_key_spki, out int read);
                if (read != receiver_public_key_spki.Length)
                    throw new CryptographicException("Не удалось полностью прочитать публичный ключ получателя (SPKI).");

                byte[] shared_secret = sender_ephemeral.DeriveKeyMaterial(receiver_public_holder.PublicKey);
                byte[] kdf_salt = sender_context?.Kdf_salt ?? RandomNumberGenerator.GetBytes(Kdf_salt_bytes);
                byte[] master_key = Derive_master_key(shared_secret, kdf_salt);
                byte[] fss_seed = Derive_fss_seed(master_key);

                // На каждый пакет создаётся собственный перемешанный алфавит.
                // Словари соответствий пересобираются заново и не переиспользуются между сообщениями.
                string shuffled_alphabet = Build_shuffled_alphabet(base_alphabet, master_key);
                Strategy_wrapper local_wrapper = Build_local_wrapper(shuffled_alphabet);

                // Симметрический ключ для текущего ФСС-ядра генерируется автоматически из seed.
                string auto_fss_key = Derive_fss_subkey_stream(fss_seed, Derived_fss_key_symbols, shuffled_alphabet);
                Cipher_options effective_options = new()
                {
                    Block_plain_text_length = options.Block_plain_text_length,
                    Key = auto_fss_key,
                    Enable_round_cipher = options.Enable_round_cipher
                };

                string fss_ciphertext = local_wrapper.Encrypt(source, effective_options);

                byte[] key_derivation_material = Build_key_derivation_material(kdf_salt);
                byte[] ephemeral_public_key_spki = sender_ephemeral.ExportSubjectPublicKeyInfo();

                return new Hybrid_cipher_package
                {
                    Ciphertext = fss_ciphertext,
                    Encrypted_symmetric_key = Base64_url_codec.Encode(key_derivation_material),
                    Ephemeral_public_key = Base64_url_codec.Encode(ephemeral_public_key_spki),
                    Block_plain_text_length = options.Block_plain_text_length,
                    Round_cipher_enabled = options.Enable_round_cipher,
                    Curve_id = Curve_id_nist_p256
                };
            }
            finally
            {
                local_sender_ephemeral?.Dispose();
            }
        }

        internal string Decrypt(Hybrid_cipher_package packet, ECDiffieHellman receiver_private_key)
        {
            // Дешифрование гибридной схемы.
            // Из packet + приватного ключа получателя восстанавливается тот же master key,
            // затем те же подключи/алфавит, после чего выполняется обратное ФСС-расшифрование.
            if (packet is null)
                throw new ArgumentNullException(nameof(packet));

            if (packet.Curve_id != Curve_id_nist_p256)
                throw new CryptographicException($"Неподдерживаемый идентификатор кривой: {packet.Curve_id}.");

            if (!Base64_url_codec.Try_decode(packet.Ephemeral_public_key, out byte[] ephemeral_public_key_spki))
                throw new CryptographicException("Поле Ephemeral_public_key не является корректным Base64/Base64URL.");

            if (!Base64_url_codec.Try_decode(packet.Encrypted_symmetric_key, out byte[] key_derivation_material))
                throw new CryptographicException("Поле Encrypted_symmetric_key не является корректным Base64/Base64URL.");

            using ECDiffieHellman sender_ephemeral_public_holder = ECDiffieHellman.Create();
            sender_ephemeral_public_holder.ImportSubjectPublicKeyInfo(ephemeral_public_key_spki, out int read);
            if (read != ephemeral_public_key_spki.Length)
                throw new CryptographicException("Не удалось полностью прочитать ephemeral публичный ключ отправителя.");

            byte[] kdf_salt = Parse_key_derivation_material(key_derivation_material);

            // Получатель восстанавливает тот же master key через свой приватный ключ
            // и ephemeral-публичный ключ отправителя.
            byte[] shared_secret = receiver_private_key.DeriveKeyMaterial(sender_ephemeral_public_holder.PublicKey);
            byte[] master_key = Derive_master_key(shared_secret, kdf_salt);
            byte[] fss_seed = Derive_fss_seed(master_key);

            string shuffled_alphabet = Build_shuffled_alphabet(base_alphabet, master_key);
            Strategy_wrapper local_wrapper = Build_local_wrapper(shuffled_alphabet);
            string auto_fss_key = Derive_fss_subkey_stream(fss_seed, Derived_fss_key_symbols, shuffled_alphabet);
            Cipher_options effective_options = new()
            {
                Block_plain_text_length = packet.Block_plain_text_length,
                Key = auto_fss_key,
                Enable_round_cipher = packet.Round_cipher_enabled
            };

            return local_wrapper.Decrypt(packet.Ciphertext, effective_options);
        }

        static byte[] Derive_master_key(byte[] shared_secret, byte[] salt)
        {
            // Фиксированный размер master key: 32 байта (256 бит).
            byte[] info = Encoding.UTF8.GetBytes(Master_key_info_label);
            return Hkdf_sha256(shared_secret, salt, info, Master_key_bytes);
        }

        static byte[] Derive_fss_seed(byte[] master_key)
        {
            // Seed, из которого разворачивается поток подключей ФСС.
            byte[] info = Encoding.UTF8.GetBytes(Fss_seed_info_label);
            return Hkdf_sha256(master_key, [], info, Fss_seed_bytes);
        }

        static byte[] Build_key_derivation_material(byte[] kdf_salt)
        {
            if (kdf_salt.Length != Kdf_salt_bytes)
                throw new CryptographicException($"Некорректная длина HKDF salt: {kdf_salt.Length}.");

            using MemoryStream memory = new();
            using BinaryWriter writer = new(memory, Encoding.UTF8, leaveOpen: true);
            writer.Write((byte)2); // версия формата: только HKDF salt, без AES-GCM wrap
            writer.Write((byte)kdf_salt.Length);
            writer.Write(kdf_salt);
            writer.Flush();

            return memory.ToArray();
        }

        static byte[] Parse_key_derivation_material(byte[] input)
        {
            // Разбор служебной структуры encrypted_symmetric_key:
            // version=2 + длина salt + salt.
            using MemoryStream memory = new(input);
            using BinaryReader reader = new(memory, Encoding.UTF8, leaveOpen: true);

            byte version = reader.ReadByte();
            if (version != 2)
                throw new CryptographicException($"Неподдерживаемая версия encrypted_symmetric_key: {version}.");

            int salt_length = reader.ReadByte();
            if (salt_length != Kdf_salt_bytes)
                throw new CryptographicException("Некорректная структура encrypted_symmetric_key.");

            byte[] kdf_salt = reader.ReadBytes(salt_length);

            if (kdf_salt.Length != salt_length)
                throw new CryptographicException("encrypted_symmetric_key оборван или повреждён.");

            if (memory.Position != memory.Length)
                throw new CryptographicException("encrypted_symmetric_key содержит лишние данные.");

            return kdf_salt;
        }

        static string Derive_fss_subkey_stream(byte[] seed, int symbols_count, string alphabet)
        {
            // Генерация строкового ключевого потока для текущего раундового слоя коэффициентов.
            // Поток детерминирован от seed и выбранного алфавита.
            if (symbols_count <= 0)
                return "";

            int alphabet_length = alphabet.Length;
            if (alphabet_length <= 0)
                throw new InvalidOperationException("Алфавит ФСС не инициализирован.");

            StringBuilder result = new(symbols_count);
            byte[] pool = [];
            int pool_index = 0;
            uint counter = 0;

            while (result.Length < symbols_count)
            {
                // При мощности алфавита 256 используем байт напрямую как индекс символа.
                if (alphabet_length == 256)
                {
                    if (pool_index >= pool.Length)
                    {
                        pool = Expand_prng_block(seed, Subkey_stream_label, counter++);
                        pool_index = 0;
                    }

                    byte value = pool[pool_index];
                    pool_index++;
                    result.Append(alphabet[value]);
                    continue;
                }

                if (pool_index + 1 >= pool.Length)
                {
                    pool = Expand_prng_block(seed, Subkey_stream_label, counter++);
                    pool_index = 0;
                }

                ushort candidate = (ushort)(pool[pool_index] | (pool[pool_index + 1] << 8));
                pool_index += 2;

                int modulus = alphabet_length;
                int range = ushort.MaxValue + 1;
                int limit = range - (range % modulus);
                if (candidate >= limit)
                    continue;

                // Для не-256 алфавитов используется unbiased sampling.
                int index = candidate % modulus;
                result.Append(alphabet[index]);
            }

            return result.ToString();
        }

        static Strategy_wrapper Build_local_wrapper(string alphabet)
        {
            // КЛЮЧЕВАЯ ТОЧКА ПЕРЕСБОРКИ СЛОВАРЕЙ:
            // Конструктор Factorial_strategy(alphabet) очищает и строит заново:
            // char_to_number, number_to_char, byte_to_char, char_to_byte.
            // Это и есть пересчёт таблиц для конкретного сообщения.
            return new Strategy_wrapper(new Factorial_strategy(alphabet));
        }

        static string Build_shuffled_alphabet(string alphabet, byte[] master_key)
        {
            // Перестановка Фишера-Йетса по детерминированному CSPRNG от master key.
            // Для одинакового master key обе стороны получают одинаковый алфавит.
            char[] symbols = alphabet.ToCharArray();
            if (symbols.Length <= 1)
                return alphabet;

            byte[] permutation_key = Derive_alphabet_permutation_key(master_key);
            byte[] pool = [];
            int pool_index = 0;
            uint counter = 0;

            for (int i = symbols.Length - 1; i > 0; i--)
            {
                int j = Next_unbiased_index(i + 1, permutation_key, ref pool, ref pool_index, ref counter);
                (symbols[i], symbols[j]) = (symbols[j], symbols[i]);
            }

            return new string(symbols);
        }

        static byte[] Derive_alphabet_permutation_key(byte[] master_key)
        {
            // Ключ только для задачи перестановки алфавита.
            byte[] info = Encoding.UTF8.GetBytes(Alphabet_permutation_info_label);
            return Hkdf_sha256(master_key, [], info, 32);
        }

        static int Next_unbiased_index(int max_exclusive, byte[] key, ref byte[] pool, ref int pool_index, ref uint counter)
        {
            if (max_exclusive <= 1)
                return 0;

            uint limit = uint.MaxValue - (uint.MaxValue % (uint)max_exclusive);

            while (true)
            {
                uint value = Next_uint32(key, ref pool, ref pool_index, ref counter);
                if (value < limit)
                    return (int)(value % (uint)max_exclusive);
            }
        }

        static uint Next_uint32(byte[] key, ref byte[] pool, ref int pool_index, ref uint counter)
        {
            if (pool_index + 4 > pool.Length)
            {
                pool = Expand_prng_block(key, Alphabet_shuffle_stream_label, counter++);
                pool_index = 0;
            }

            uint value =
                (uint)(pool[pool_index] << 24) |
                (uint)(pool[pool_index + 1] << 16) |
                (uint)(pool[pool_index + 2] << 8) |
                pool[pool_index + 3];

            pool_index += 4;
            return value;
        }

        static byte[] Expand_prng_block(byte[] key, string label, uint counter)
        {
            byte[] label_bytes = Encoding.UTF8.GetBytes(label);
            byte[] message = new byte[label_bytes.Length + 4];
            Array.Copy(label_bytes, 0, message, 0, label_bytes.Length);

            message[^4] = (byte)(counter >> 24);
            message[^3] = (byte)(counter >> 16);
            message[^2] = (byte)(counter >> 8);
            message[^1] = (byte)counter;

            using HMACSHA256 hmac = new(key);
            return hmac.ComputeHash(message);
        }

        static byte[] Hkdf_sha256(byte[] ikm, byte[] salt, byte[] info, int output_length)
        {
            // Реализация HKDF-SHA256 (Extract + Expand).
            // Используется для вывода всех производных ключей из shared secret/master key.
            if (output_length <= 0)
                return [];

            byte[] effective_salt = salt.Length == 0 ? new byte[32] : salt;

            byte[] prk;
            using (HMACSHA256 extract_hmac = new(effective_salt))
                prk = extract_hmac.ComputeHash(ikm);

            byte[] output = new byte[output_length];
            byte[] previous = [];
            int offset = 0;
            byte block_index = 1;

            while (offset < output_length)
            {
                byte[] input = new byte[previous.Length + info.Length + 1];
                Array.Copy(previous, 0, input, 0, previous.Length);
                Array.Copy(info, 0, input, previous.Length, info.Length);
                input[^1] = block_index;

                using HMACSHA256 expand_hmac = new(prk);
                previous = expand_hmac.ComputeHash(input);

                int to_copy = Math.Min(previous.Length, output_length - offset);
                Array.Copy(previous, 0, output, offset, to_copy);
                offset += to_copy;
                block_index++;
            }

            return output;
        }
    }
}
