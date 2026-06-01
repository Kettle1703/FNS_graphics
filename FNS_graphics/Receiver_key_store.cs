using System;
using System.IO;
using System.Security.Cryptography;
using FNS_rebuild;

namespace FNS_graphics
{
    internal static class Receiver_key_store
    {
        internal static ECDiffieHellman LoadOrCreate(string private_key_path, string public_key_path)
        {
            // Загружает существующий приватный ключ получателя или создаёт новый.
            if (File.Exists(private_key_path))
            {
                string private_b64 = File.ReadAllText(private_key_path);
                if (!Base64_url_codec.Try_decode(private_b64, out byte[] private_bytes))
                    throw new CryptographicException("Файл приватного ключа получателя содержит некорректный Base64/Base64URL.");

                ECDiffieHellman imported = ECDiffieHellman.Create();
                imported.ImportPkcs8PrivateKey(private_bytes, out int read);
                if (read != private_bytes.Length)
                    throw new CryptographicException("Не удалось полностью прочитать приватный ECDH-ключ получателя.");

                if (!File.Exists(public_key_path))
                {
                    byte[] public_bytes = imported.ExportSubjectPublicKeyInfo();
                    File.WriteAllText(public_key_path, Base64_url_codec.Encode(public_bytes));
                }

                return imported;
            }

            ECDiffieHellman created = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] private_key = created.ExportPkcs8PrivateKey();
            byte[] public_key = created.ExportSubjectPublicKeyInfo();

            File.WriteAllText(private_key_path, Base64_url_codec.Encode(private_key));
            File.WriteAllText(public_key_path, Base64_url_codec.Encode(public_key));

            return created;
        }
    }
}
