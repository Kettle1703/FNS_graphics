using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using static System.Console;
using Digit = System.UInt16;
using System.IO.Hashing;
using System.Text;
using Witteborn.ReedSolomon;

namespace FNS_rebuild
{
    internal sealed class Transmission_packet
    {
        // Внешний пакет защиты канала передачи.
        // Хранит шардированную нагрузку и контрольные суммы для обнаружения повреждений.
        public int Data_shards { get; set; } = 8;
        public int Parity_shards { get; set; } = 4;
        public int Padding_size { get; set; } = 0;
        public uint Payload_crc32 { get; set; } = 0;
        public List<string?> Shards_base64 { get; set; } = [];
        public List<uint> Shard_crc32 { get; set; } = [];
    }

    internal sealed class Transmission_error_protection
    {
        // Наружный слой: Reed-Solomon + CRC.
        // Он работает поверх сериализованного JSON-пакета гибридного шифрования.

        internal Transmission_packet Protect(string payload_json, int data_shards = 8, int parity_shards = 4)
        {
            if (payload_json is null)
                throw new ArgumentNullException(nameof(payload_json));
            if (data_shards < 1)
                throw new ArgumentOutOfRangeException(nameof(data_shards), "Количество data_shards должно быть >= 1.");
            if (parity_shards < 1)
                throw new ArgumentOutOfRangeException(nameof(parity_shards), "Количество parity_shards должно быть >= 1.");

            byte[] payload = Encoding.UTF8.GetBytes(payload_json);
            ReedSolomon rs = new(data_shards, parity_shards);

            int padding_size = rs.GetPaddingSize(payload.Length, data_shards);
            byte[][] shards = rs.ManagedEncode(payload, data_shards, parity_shards);

            List<string?> shards_base64 = new(shards.Length);
            List<uint> shard_crc32 = new(shards.Length);

            for (int i = 0; i < shards.Length; i++)
            {
                byte[] shard = shards[i];
                shards_base64.Add(Convert.ToBase64String(shard));
                shard_crc32.Add(Crc32.HashToUInt32(shard));
            }

            return new Transmission_packet
            {
                Data_shards = data_shards,
                Parity_shards = parity_shards,
                Padding_size = padding_size,
                Payload_crc32 = Crc32.HashToUInt32(payload),
                Shards_base64 = shards_base64,
                Shard_crc32 = shard_crc32
            };
        }

        internal string Recover(Transmission_packet packet)
        {
            if (packet is null)
                throw new ArgumentNullException(nameof(packet));

            int total_shards = packet.Data_shards + packet.Parity_shards;
            if (packet.Data_shards < 1 || packet.Parity_shards < 1)
                throw new InvalidOperationException("Некорректные параметры Reed-Solomon в пакете.");
            if (packet.Shards_base64.Count != total_shards || packet.Shard_crc32.Count != total_shards)
                throw new InvalidOperationException("Некорректное количество шардов или контрольных сумм в пакете.");

            byte[][] shards = new byte[total_shards][];
            int missing_or_damaged = 0;

            // Любой шард с неверной CRC считаем потерянным, чтобы RS мог его восстановить.
            for (int i = 0; i < total_shards; i++)
            {
                string? encoded = packet.Shards_base64[i];
                if (string.IsNullOrWhiteSpace(encoded))
                {
                    shards[i] = null!;
                    missing_or_damaged++;
                    continue;
                }

                byte[] shard;
                try
                {
                    shard = Convert.FromBase64String(encoded);
                }
                catch (FormatException)
                {
                    shards[i] = null!;
                    missing_or_damaged++;
                    continue;
                }

                uint actual_crc = Crc32.HashToUInt32(shard);
                if (actual_crc != packet.Shard_crc32[i])
                {
                    shards[i] = null!;
                    missing_or_damaged++;
                    continue;
                }

                shards[i] = shard;
            }

            if (missing_or_damaged > packet.Parity_shards)
                throw new InvalidOperationException($"Слишком много повреждённых/утраченных шардов: {missing_or_damaged}, максимум восстанавливаемых: {packet.Parity_shards}.");

            ReedSolomon rs = new(packet.Data_shards, packet.Parity_shards);
            byte[] restored_payload = rs.ManagedDecode(shards, packet.Data_shards, packet.Parity_shards, packet.Padding_size);

            uint payload_crc = Crc32.HashToUInt32(restored_payload);
            if (payload_crc != packet.Payload_crc32)
                throw new InvalidOperationException("CRC полезной нагрузки не совпал после восстановления: пакет повреждён.");

            return Encoding.UTF8.GetString(restored_payload);
        }
    }
}
