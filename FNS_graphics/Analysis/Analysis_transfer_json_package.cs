using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FNS_rebuild
{
    internal sealed class Analysis_transfer_json_package
    {
        [JsonPropertyOrder(1)]
        public string Ephemeral_public_key { get; set; } = string.Empty;

        [JsonPropertyOrder(2)]
        public string Ephemeral_public_key_signature { get; set; } = string.Empty;

        [JsonPropertyOrder(3)]
        public string Sender_signing_key_fingerprint { get; set; } = string.Empty;

        [JsonPropertyOrder(4)]
        public string Key_derivation_salt { get; set; } = string.Empty;

        [JsonPropertyOrder(5)]
        public bool Round_cipher_enabled { get; set; } = true;

        [JsonPropertyOrder(6)]
        public string Encryption_core { get; set; } = Encryption_core_catalog.Factorial_id;

        [JsonPropertyOrder(7)]
        public string Ciphertext { get; set; } = string.Empty;
    }

    internal static class Analysis_transfer_json_builder
    {
        static readonly JsonSerializerOptions Payload_options = new()
        {
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        internal static string Build_payload_json(string ciphertext, Cipher_options options)
        {
            Analysis_transfer_json_package payload = new()
            {
                Ephemeral_public_key = Base64_url_codec.Encode([1]),
                Ephemeral_public_key_signature = string.Empty,
                Sender_signing_key_fingerprint = string.Empty,
                Key_derivation_salt = Base64_url_codec.Encode([2]),
                Round_cipher_enabled = options.Enable_round_cipher,
                Encryption_core = Encryption_core_catalog.To_storage_id(options.Encryption_core),
                Ciphertext = ciphertext
            };

            return JsonSerializer.Serialize(payload, Payload_options);
        }
    }
}
