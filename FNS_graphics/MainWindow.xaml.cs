using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using FNS_rebuild;

namespace FNS_graphics
{
    public partial class MainWindow : Window
    {
        public static readonly RoutedUICommand EncryptCommand = new(
            "Encrypt",
            nameof(EncryptCommand),
            typeof(MainWindow));

        public static readonly RoutedUICommand DecryptCommand = new(
            "Decrypt",
            nameof(DecryptCommand),
            typeof(MainWindow));

        private static readonly string ReceiverPrivateKeyPath = Path.Combine(AppContext.BaseDirectory, "receiver_ecdh_private.pk8.b64");
        private static readonly string ReceiverPublicKeyPath = Path.Combine(AppContext.BaseDirectory, "receiver_ecdh_public.spki.b64");
        private const int DefaultBlockLength = 1096;

        private readonly Strategy_wrapper _wrapper;
        private readonly Hybrid_fns_cryptosystem _hybrid;
        private readonly ECDiffieHellman _receiverPrivateKey;
        private readonly byte[] _receiverPublicKeySpki;
        private readonly List<TextBox> _highlightedTextBoxes = [];
        private const string AutoPlaceholder = "<заполняется автоматически>";

        public MainWindow()
        {
            InitializeComponent();

            _wrapper = new Strategy_wrapper(new Factorial_strategy());
            _hybrid = new Hybrid_fns_cryptosystem(_wrapper);
            _receiverPrivateKey = LoadOrCreateReceiverPrivateKey();
            _receiverPublicKeySpki = _receiverPrivateKey.ExportSubjectPublicKeyInfo();

            SharedSenderPublicKeyTextBox.Text = AutoPlaceholder;
            SharedReceiverPublicKeyTextBox.Text = Convert.ToBase64String(_receiverPublicKeySpki);
            SharedSessionKeyTextBox.Text = AutoPlaceholder;
            TransferCipherTextTextBox.Text = string.Empty;

            EncryptMetricsTextBlock.Text = "Время: - | Длина: -";
            DecryptMetricsTextBlock.Text = "Время: - | Длина: -";
            StatusTextBlock.Text = "Нажмите «Шифровать» для автозаполнения полей передачи.";
        }

        protected override void OnClosed(EventArgs e)
        {
            _receiverPrivateKey.Dispose();
            base.OnClosed(e);
        }

        private void CopyField_Click(object sender, RoutedEventArgs e)
        {
            ClearPersistentHighlights();

            if (sender is not Button { Tag: TextBox source })
                return;

            string text = source.Text ?? string.Empty;
            if (text.Length == 0)
            {
                StatusTextBlock.Text = "Поле пустое, копировать нечего.";
                return;
            }

            Clipboard.SetText(text);
            StatusTextBlock.Text = "Содержимое поля скопировано в буфер обмена.";
        }

        private void EncryptCommand_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            Encrypt_Click(sender, new RoutedEventArgs());
        }

        private void DecryptCommand_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            Decrypt_Click(sender, new RoutedEventArgs());
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            ClearPersistentHighlights();

            try
            {
                string source = SourceTextBox.Text ?? string.Empty;
                if (string.IsNullOrEmpty(source))
                {
                    StatusTextBlock.Text = "Введите исходный текст для шифрования.";
                    return;
                }

                string receiverPublicBase64 = SharedReceiverPublicKeyTextBox.Text?.Trim() ?? string.Empty;
                byte[] receiverPublicSpki = string.IsNullOrEmpty(receiverPublicBase64) || receiverPublicBase64 == AutoPlaceholder
                    ? _receiverPublicKeySpki
                    : Convert.FromBase64String(receiverPublicBase64);
                Cipher_options options = new()
                {
                    Block_plain_text_length = DefaultBlockLength,
                    Key = string.Empty
                };

                Stopwatch watch = Stopwatch.StartNew();
                Hybrid_cipher_package packet = _hybrid.Encrypt(source, receiverPublicSpki, options);
                watch.Stop();

                TransferCipherTextTextBox.Text = packet.Ciphertext;
                SharedSenderPublicKeyTextBox.Text = packet.Ephemeral_public_key;
                SharedSessionKeyTextBox.Text = packet.Encrypted_symmetric_key;

                EncryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {source.Length}";
                MarkPersistentHighlights(
                    TransferCipherTextTextBox,
                    SharedSenderPublicKeyTextBox,
                    SharedSessionKeyTextBox);

                StatusTextBlock.Text = "Шифрование выполнено. Данные для передачи заполнены в общем блоке.";
            }
            catch (FormatException)
            {
                StatusTextBlock.Text = "Публичный ключ получателя должен быть в формате Base64.";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка шифрования: {ex.Message}";
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            ClearPersistentHighlights();

            try
            {
                string ciphertext = TransferCipherTextTextBox.Text ?? string.Empty;
                string senderPublicKey = SharedSenderPublicKeyTextBox.Text?.Trim() ?? string.Empty;
                string encryptedSymmetricKey = SharedSessionKeyTextBox.Text?.Trim() ?? string.Empty;

                if (string.IsNullOrWhiteSpace(ciphertext) || ciphertext.StartsWith("<"))
                {
                    StatusTextBlock.Text = "Поле шифротекста не заполнено.";
                    return;
                }

                if (string.IsNullOrWhiteSpace(senderPublicKey) || senderPublicKey == AutoPlaceholder)
                {
                    StatusTextBlock.Text = "Поле ключа отправителя не заполнено.";
                    return;
                }

                if (string.IsNullOrWhiteSpace(encryptedSymmetricKey) || encryptedSymmetricKey == AutoPlaceholder)
                {
                    StatusTextBlock.Text = "Поле защищённого сеансового ключа не заполнено.";
                    return;
                }

                Hybrid_cipher_package packet = new()
                {
                    Ciphertext = ciphertext,
                    Ephemeral_public_key = senderPublicKey,
                    Encrypted_symmetric_key = encryptedSymmetricKey,
                    Block_plain_text_length = DefaultBlockLength,
                    Curve_id = Hybrid_fns_cryptosystem.Curve_id_nist_p256
                };

                Stopwatch watch = Stopwatch.StartNew();
                string decrypted = _hybrid.Decrypt(packet, _receiverPrivateKey);
                watch.Stop();

                SourceTextBox.Text = decrypted;
                DecryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {ciphertext.Length}";
                MarkPersistentHighlights(SourceTextBox);
                StatusTextBlock.Text = "Дешифрование выполнено. Текст записан в поле «Исходный текст».";
            }
            catch (FormatException)
            {
                StatusTextBlock.Text = "Ключи пакета должны быть в формате Base64.";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка дешифрования: {ex.Message}";
            }
        }

        private void MarkPersistentHighlights(params TextBox[] textBoxes)
        {
            Brush highlightBackground = new SolidColorBrush(Color.FromRgb(236, 249, 234));
            Brush highlightBorder = new SolidColorBrush(Color.FromRgb(92, 151, 112));

            foreach (TextBox box in textBoxes)
            {
                box.Background = highlightBackground;
                box.BorderBrush = highlightBorder;
                box.BorderThickness = new Thickness(2);
                _highlightedTextBoxes.Add(box);
            }
        }

        private void ClearPersistentHighlights()
        {
            if (_highlightedTextBoxes.Count == 0)
                return;

            Brush normalBackground = Brushes.White;
            Brush normalBorder = new SolidColorBrush(Color.FromRgb(182, 204, 184));

            foreach (TextBox box in _highlightedTextBoxes)
            {
                box.Background = normalBackground;
                box.BorderBrush = normalBorder;
                box.BorderThickness = new Thickness(1);
            }

            _highlightedTextBoxes.Clear();
        }

        private static ECDiffieHellman LoadOrCreateReceiverPrivateKey()
        {
            if (File.Exists(ReceiverPrivateKeyPath))
            {
                string privateB64 = File.ReadAllText(ReceiverPrivateKeyPath).Trim();
                byte[] privateBytes = Convert.FromBase64String(privateB64);

                ECDiffieHellman imported = ECDiffieHellman.Create();
                imported.ImportPkcs8PrivateKey(privateBytes, out int read);
                if (read != privateBytes.Length)
                    throw new CryptographicException("Не удалось полностью прочитать приватный ECDH-ключ получателя.");

                if (!File.Exists(ReceiverPublicKeyPath))
                {
                    byte[] publicBytes = imported.ExportSubjectPublicKeyInfo();
                    File.WriteAllText(ReceiverPublicKeyPath, Convert.ToBase64String(publicBytes));
                }

                return imported;
            }

            ECDiffieHellman created = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] privateKey = created.ExportPkcs8PrivateKey();
            byte[] publicKey = created.ExportSubjectPublicKeyInfo();

            File.WriteAllText(ReceiverPrivateKeyPath, Convert.ToBase64String(privateKey));
            File.WriteAllText(ReceiverPublicKeyPath, Convert.ToBase64String(publicKey));

            return created;
        }
    }
}
