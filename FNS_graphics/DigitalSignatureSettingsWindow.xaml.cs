using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

namespace FNS_graphics
{
    public partial class DigitalSignatureSettingsWindow : Window
    {
        bool settings_loaded_from_store;
        string active_sender_signing_public_key = string.Empty;
        string generated_sender_public_key_pending = string.Empty;
        string generated_sender_private_key_pending = string.Empty;

        readonly List<Sender_signing_key_entry> own_sender_signing_keys = [];
        readonly List<string> trusted_sender_public_keys = [];

        public DigitalSignatureSettingsWindow()
        {
            InitializeComponent();
        }

        void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Заполняет окно значениями из локального хранилища настроек подписи.
            Digital_signature_settings settings = Digital_signature_store.Get_settings_snapshot();

            SignCiphertextCheckBox.IsChecked = settings.Sign_ciphertext;

            own_sender_signing_keys.Clear();
            foreach (Sender_signing_key_entry source in settings.Own_sender_signing_keys)
            {
                string normalized_public = Normalize_base64_text(source.Public_key);
                string normalized_private = Normalize_base64_text(source.Private_key_pkcs8);
                if (normalized_public.Length == 0 || normalized_private.Length == 0)
                    continue;

                if (!Try_validate_sender_public_key_spki(normalized_public, out _))
                    continue;

                if (!Try_validate_sender_private_key_pkcs8(normalized_private, out _))
                    continue;

                if (!own_sender_signing_keys.Exists(value => string.Equals(value.Public_key, normalized_public, StringComparison.Ordinal)))
                {
                    own_sender_signing_keys.Add(new Sender_signing_key_entry
                    {
                        Public_key = normalized_public,
                        Private_key_pkcs8 = normalized_private
                    });
                }
            }

            active_sender_signing_public_key = Normalize_base64_text(settings.Active_sender_signing_public_key);
            if (active_sender_signing_public_key.Length == 0 ||
                !own_sender_signing_keys.Exists(value => string.Equals(value.Public_key, active_sender_signing_public_key, StringComparison.Ordinal)))
            {
                active_sender_signing_public_key = own_sender_signing_keys.Count > 0
                    ? own_sender_signing_keys[0].Public_key
                    : string.Empty;
            }

            generated_sender_public_key_pending = string.Empty;
            generated_sender_private_key_pending = string.Empty;
            OwnSenderPublicKeyTextBox.Text = string.Empty;

            trusted_sender_public_keys.Clear();
            foreach (string key in settings.Trusted_sender_long_term_public_keys)
            {
                string normalized = Normalize_base64_text(key);
                if (normalized.Length == 0)
                    continue;

                if (!trusted_sender_public_keys.Exists(value => string.Equals(value, normalized, StringComparison.Ordinal)))
                    trusted_sender_public_keys.Add(normalized);
            }

            TrustedSenderPublicKeyTextBox.Text = string.Empty;

            Refresh_own_sender_keys_list();
            Refresh_trusted_sender_keys_list();
            settings_loaded_from_store = true;
        }

        void Window_Closed(object? sender, EventArgs e)
        {
            // Сохраняет изменения настроек подписи при закрытии окна.
            if (!settings_loaded_from_store)
                return;

            Digital_signature_store.Save_settings(new Digital_signature_settings
            {
                Sign_ciphertext = SignCiphertextCheckBox.IsChecked != false,
                Active_sender_signing_public_key = active_sender_signing_public_key,
                Own_sender_signing_keys =
                [
                    .. own_sender_signing_keys.ConvertAll(static value => new Sender_signing_key_entry
                    {
                        Public_key = value.Public_key,
                        Private_key_pkcs8 = value.Private_key_pkcs8
                    })
                ],
                Trusted_sender_long_term_public_keys = [.. trusted_sender_public_keys]
            });
        }

        void GenerateSenderLongTermKeyButton_Click(object sender, RoutedEventArgs e)
        {
            // Генерирует новую долгосрочную пару подписи отправителя и подставляет публичный ключ в поле.
            try
            {
                Sender_signing_key_entry generated_key = Digital_signature_store.Generate_sender_long_term_key_pair_entry();
                generated_sender_public_key_pending = Normalize_base64_text(generated_key.Public_key);
                generated_sender_private_key_pending = Normalize_base64_text(generated_key.Private_key_pkcs8);

                OwnSenderPublicKeyTextBox.Text = generated_sender_public_key_pending;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    this,
                    $"Ошибка генерации долгосрочного ключа подписи: {ex.Message}",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        void AddOwnSenderKeyButton_Click(object sender, RoutedEventArgs e)
        {
            string key = Normalize_base64_text(OwnSenderPublicKeyTextBox.Text);
            if (key.Length == 0)
            {
                MessageBox.Show(
                    this,
                    "Поле публичного ключа пустое. Сначала введите или сгенерируйте ключ.",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (!Try_validate_sender_public_key_spki(key, out string validation_error))
            {
                MessageBox.Show(
                    this,
                    validation_error,
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            if (own_sender_signing_keys.Exists(value => string.Equals(value.Public_key, key, StringComparison.Ordinal)))
            {
                MessageBox.Show(
                    this,
                    "Этот ключ уже есть в списке ваших ключей.",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (!string.Equals(key, generated_sender_public_key_pending, StringComparison.Ordinal) ||
                generated_sender_private_key_pending.Length == 0)
            {
                MessageBox.Show(
                    this,
                    "Для этого публичного ключа нет приватной части в приложении. Сначала сгенерируйте ключ кнопкой «Сгенерировать ключ».",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            own_sender_signing_keys.Add(new Sender_signing_key_entry
            {
                Public_key = key,
                Private_key_pkcs8 = generated_sender_private_key_pending
            });

            if (active_sender_signing_public_key.Length == 0)
                active_sender_signing_public_key = key;

            Refresh_own_sender_keys_list();
        }

        void SelectOwnSenderKeyButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string key })
                return;

            string normalized = Normalize_base64_text(key);
            if (normalized.Length == 0)
                return;

            if (!own_sender_signing_keys.Exists(value => string.Equals(value.Public_key, normalized, StringComparison.Ordinal)))
                return;

            active_sender_signing_public_key = normalized;
            Refresh_own_sender_keys_list();
        }

        void RemoveOwnSenderKeyButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string key })
                return;

            string normalized = Normalize_base64_text(key);
            if (normalized.Length == 0)
                return;

            own_sender_signing_keys.RemoveAll(value => string.Equals(value.Public_key, normalized, StringComparison.Ordinal));

            if (string.Equals(active_sender_signing_public_key, normalized, StringComparison.Ordinal))
            {
                active_sender_signing_public_key = own_sender_signing_keys.Count > 0
                    ? own_sender_signing_keys[0].Public_key
                    : string.Empty;
            }

            Refresh_own_sender_keys_list();
        }

        void AddTrustedSenderKeyButton_Click(object sender, RoutedEventArgs e)
        {
            string key = Normalize_base64_text(TrustedSenderPublicKeyTextBox.Text);
            if (key.Length == 0)
            {
                MessageBox.Show(
                    this,
                    "Поле доверенного публичного ключа пустое.",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (!Try_validate_sender_public_key_spki(key, out string validation_error))
            {
                MessageBox.Show(
                    this,
                    validation_error,
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            if (trusted_sender_public_keys.Exists(value => string.Equals(value, key, StringComparison.Ordinal)))
            {
                MessageBox.Show(
                    this,
                    "Этот ключ уже есть в списке доверенных.",
                    "Цифровая подпись",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            trusted_sender_public_keys.Add(key);
            Refresh_trusted_sender_keys_list();
        }

        void RemoveTrustedSenderKeyButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string key })
                return;

            trusted_sender_public_keys.RemoveAll(value => string.Equals(value, key, StringComparison.Ordinal));
            Refresh_trusted_sender_keys_list();
        }

        void Refresh_own_sender_keys_list()
        {
            List<Own_sender_key_view_item> view_items = [];
            foreach (Sender_signing_key_entry key in own_sender_signing_keys)
            {
                bool is_active = string.Equals(key.Public_key, active_sender_signing_public_key, StringComparison.Ordinal);
                view_items.Add(new Own_sender_key_view_item
                {
                    Public_key = key.Public_key,
                    Active_label = is_active ? "Активный" : string.Empty,
                    Can_select = !is_active
                });
            }

            OwnSenderSigningKeysListBox.ItemsSource = null;
            OwnSenderSigningKeysListBox.ItemsSource = view_items;
        }

        void Refresh_trusted_sender_keys_list()
        {
            TrustedSenderKeysListBox.ItemsSource = null;
            TrustedSenderKeysListBox.ItemsSource = trusted_sender_public_keys;
        }

        static string Normalize_base64_text(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string source = value.Trim();
            char[] buffer = new char[source.Length];
            int written = 0;
            foreach (char ch in source)
            {
                if (!char.IsWhiteSpace(ch))
                    buffer[written++] = ch;
            }

            return written == 0 ? string.Empty : new string(buffer, 0, written);
        }

        static bool Try_validate_sender_public_key_spki(string key_base64, out string error_message)
        {
            error_message = string.Empty;

            if (!Try_decode_base64(key_base64, out byte[] key_bytes))
            {
                error_message = "Ключ должен быть корректной Base64-строкой.";
                return false;
            }

            try
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(key_bytes, out int read);
                if (read != key_bytes.Length)
                {
                    error_message = "Ключ прочитан не полностью. Ожидается полный SPKI-публичный ключ ECDSA.";
                    return false;
                }

                return true;
            }
            catch
            {
                error_message = "Ключ не похож на корректный SPKI-публичный ключ ECDSA.";
                return false;
            }
        }

        static bool Try_validate_sender_private_key_pkcs8(string key_base64, out string error_message)
        {
            error_message = string.Empty;

            if (!Try_decode_base64(key_base64, out byte[] key_bytes))
            {
                error_message = "Приватный ключ должен быть корректной Base64-строкой.";
                return false;
            }

            try
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(key_bytes, out int read);
                if (read != key_bytes.Length)
                {
                    error_message = "Приватный ключ прочитан не полностью. Ожидается полный PKCS8-ключ ECDSA.";
                    return false;
                }

                return true;
            }
            catch
            {
                error_message = "Приватный ключ не похож на корректный PKCS8-ключ ECDSA.";
                return false;
            }
        }

        static bool Try_decode_base64(string encoded, out byte[] bytes)
        {
            int buffer_length = ((encoded.Length + 3) / 4) * 3;
            byte[] buffer = new byte[buffer_length];

            if (!Convert.TryFromBase64String(encoded, buffer, out int written))
            {
                bytes = [];
                return false;
            }

            if (written == buffer_length)
            {
                bytes = buffer;
                return true;
            }

            bytes = new byte[written];
            Array.Copy(buffer, bytes, written);
            return true;
        }

        sealed class Own_sender_key_view_item
        {
            public string Public_key { get; init; } = string.Empty;
            public string Active_label { get; init; } = string.Empty;
            public bool Can_select { get; init; }
        }
    }
}
