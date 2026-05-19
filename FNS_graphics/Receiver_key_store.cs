using System;
using System.IO;
using System.Security.Cryptography;

namespace FNS_graphics
{
    internal static class Receiver_key_store
    {
        internal static ECDiffieHellman LoadOrCreate(string private_key_path, string public_key_path)
        {
            // Загружает существующий приватный ключ получателя или создаёт новый.
            if (File.Exists(private_key_path))
            {
                string private_b64 = File.ReadAllText(private_key_path).Trim();
                byte[] private_bytes = Convert.FromBase64String(private_b64);

                ECDiffieHellman imported = ECDiffieHellman.Create();
                imported.ImportPkcs8PrivateKey(private_bytes, out int read);
                if (read != private_bytes.Length)
                    throw new CryptographicException("Не удалось полностью прочитать приватный ECDH-ключ получателя.");

                if (!File.Exists(public_key_path))
                {
                    byte[] public_bytes = imported.ExportSubjectPublicKeyInfo();
                    File.WriteAllText(public_key_path, Convert.ToBase64String(public_bytes));
                }

                return imported;
            }

            ECDiffieHellman created = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] private_key = created.ExportPkcs8PrivateKey();
            byte[] public_key = created.ExportSubjectPublicKeyInfo();

            File.WriteAllText(private_key_path, Convert.ToBase64String(private_key));
            File.WriteAllText(public_key_path, Convert.ToBase64String(public_key));

            return created;
        }
    }
}
