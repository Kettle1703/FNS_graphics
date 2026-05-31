using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
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
        private static readonly string TransferJsonDirectoryPath =
            @"C:\Users\Mikhail\Desktop\Диплом\Программирование\FNS_graphics\FNS_graphics\encrypted_packets";

        private static readonly JsonSerializerOptions TransferJsonSerializerOptions = new()
        {
            WriteIndented = true
        };
        private const int DefaultBlockLength = 1096;

        private Strategy_wrapper? _wrapper;
        private Hybrid_fns_cryptosystem? _hybrid;
        private readonly ECDiffieHellman _receiverPrivateKey;
        private readonly byte[] _receiverPublicKeySpki;
        private readonly List<TextBox> _highlightedTextBoxes = [];
        private Hybrid_sender_context? _manualSenderContext;
        private Hybrid_cipher_package? _lastEncryptedPacket;
        private bool _warmUpCompleted;
        private bool _warmUpInProgress;
        private const string AutoPlaceholder = "<заполняется автоматически>";
        private const string LinksRequiredStatusMessage = "Для шифрования или дешифрования необходимо настроить связи ключей.";

        public MainWindow()
        {
            // Инициализирует окно и базовые поля интерфейса.
            InitializeComponent();

            _receiverPrivateKey = Receiver_key_store.LoadOrCreate(ReceiverPrivateKeyPath, ReceiverPublicKeyPath);
            _receiverPublicKeySpki = _receiverPrivateKey.ExportSubjectPublicKeyInfo();

            SharedSenderPublicKeyTextBox.Text = AutoPlaceholder;
            SharedSenderPublicKeySignatureTextBox.Text = string.Empty;
            SharedReceiverPublicKeyTextBox.Text = Convert.ToBase64String(_receiverPublicKeySpki);
            SharedSessionKeyTextBox.Text = AutoPlaceholder;
            TransferCipherTextTextBox.Text = string.Empty;

            EncryptMetricsTextBlock.Text = "Время: - | Длина: -";
            DecryptMetricsTextBlock.Text = "Время: - | Длина: -";
            StatusTextBlock.Text = "Подготовка словарей шифрования...";
            SetCryptographyActionsEnabled(false);
            Try_ensure_transfer_json_directory_exists();
        }

        protected override void OnClosed(EventArgs e)
        {
            // Освобождает ресурсы окна при закрытии.
            DisposeManualSenderContext();
            _receiverPrivateKey.Dispose();
            base.OnClosed(e);
        }

        private void CopyField_Click(object sender, RoutedEventArgs e)
        {
            // Копирует содержимое выбранного поля в буфер обмена.
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
            // Запускает шифрование по команде клавиатуры.
            Encrypt_Click(sender, new RoutedEventArgs());
        }

        private void DecryptCommand_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            // Запускает дешифрование по команде клавиатуры.
            Decrypt_Click(sender, new RoutedEventArgs());
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Загружает словари шифрования после отображения окна.
            if (_warmUpCompleted || _warmUpInProgress)
                return;

            _warmUpInProgress = true;
            try
            {
                Stopwatch watch = Stopwatch.StartNew();
                await Task.Run(Factorial_strategy.Warm_up);
                watch.Stop();

                _warmUpCompleted = true;
                SetCryptographyActionsEnabled(true);
                StatusTextBlock.Text = $"Словари шифрования загружены ({watch.Elapsed.TotalMilliseconds:F0} мс).";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка загрузки словарей: {ex.Message}";
            }
            finally
            {
                _warmUpInProgress = false;
            }
        }

        private void AutoSenderKeyGenerationChanged(object sender, RoutedEventArgs e)
        {
            // Переключает режим генерации ключа отправителя.
            if (!IsLoaded)
                return;

            if (IsAutoSenderKeyGenerationEnabled())
            {
                DisposeManualSenderContext();
                StatusTextBlock.Text = "Автогенерация новых ключей отправителя включена.";
                return;
            }

            if (!EnsureHybridReady())
                return;

            _manualSenderContext ??= _hybrid!.Create_sender_context();
            StatusTextBlock.Text = "Автогенерация отключена. Ключ отправителя и защищённый сеансовый ключ будут постоянными.";
        }

        private void DigitalSignatureSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            // Открывает окно настроек цифровой подписи.
            DigitalSignatureSettingsWindow settingsWindow = new()
            {
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };

            settingsWindow.Show();
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            // Выполняет шифрование и заполняет поля передачи.
            ClearPersistentHighlights();
            if (!EnsureHybridReady())
                return;

            if (!EnsureRecipientLinksConfigured())
                return;

            if (!Window_input_validation.TryBuildEncryptRequest(
                    SourceTextBox.Text,
                    SharedReceiverPublicKeyTextBox.Text,
                    _receiverPublicKeySpki,
                    DefaultBlockLength,
                    AutoPlaceholder,
                    out Encrypt_request request,
                    out string validation_error))
            {
                StatusTextBlock.Text = validation_error;
                return;
            }

            try
            {
                Hybrid_sender_context? senderContext = IsAutoSenderKeyGenerationEnabled()
                    ? null
                    : GetOrCreateManualSenderContext();

                Stopwatch watch = Stopwatch.StartNew();
                Hybrid_cipher_package packet = _hybrid!.Encrypt(
                    request.Source_text,
                    request.Receiver_public_spki,
                    request.Options,
                    senderContext);

                Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
                if (signature_settings.Sign_ciphertext)
                {
                    if (!Digital_signature_store.Try_sign_cipher_package(
                            packet,
                            out string signature_base64,
                            out string signing_error))
                    {
                        StatusTextBlock.Text = signing_error;
                        return;
                    }

                    packet.Ephemeral_public_key_signature = signature_base64;
                }
                else
                {
                    packet.Ephemeral_public_key_signature = string.Empty;
                }

                watch.Stop();

                _lastEncryptedPacket = Clone_packet(packet);
                TransferCipherTextTextBox.Text = packet.Ciphertext;
                SharedSenderPublicKeyTextBox.Text = packet.Ephemeral_public_key;
                SharedSenderPublicKeySignatureTextBox.Text = packet.Ephemeral_public_key_signature;
                SharedSessionKeyTextBox.Text = packet.Encrypted_symmetric_key;

                EncryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {request.Source_text.Length}";
                MarkPersistentHighlights(
                    TransferCipherTextTextBox,
                    SharedSenderPublicKeyTextBox,
                    SharedSenderPublicKeySignatureTextBox,
                    SharedSessionKeyTextBox);

                StatusTextBlock.Text = signature_settings.Sign_ciphertext
                    ? "Шифрование выполнено. Пакет подписан долгосрочным ключом отправителя."
                    : "Шифрование выполнено. Данные для передачи заполнены в общем блоке.";

                if (IsBuildJsonFileEnabled())
                {
                    if (Try_export_transfer_json(packet, out string file_path, out string export_error))
                    {
                        StatusTextBlock.Text += $"{Environment.NewLine}Расположение созданного файла: {file_path}";
                    }
                    else
                    {
                        StatusTextBlock.Text += $"{Environment.NewLine}JSON файл не создан: {export_error}";
                    }
                }
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка шифрования: {ex.Message}";
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            // Выполняет дешифрование и записывает исходный текст.
            ClearPersistentHighlights();
            if (!EnsureHybridReady())
                return;

            if (!EnsureRecipientLinksConfigured())
                return;

            if (!Window_input_validation.TryBuildDecryptPacket(
                    TransferCipherTextTextBox.Text,
                    SharedSenderPublicKeyTextBox.Text,
                    SharedSessionKeyTextBox.Text,
                    SharedSenderPublicKeySignatureTextBox.Text,
                    DefaultBlockLength,
                    AutoPlaceholder,
                    out Hybrid_cipher_package packet,
                    out string validation_error))
            {
                StatusTextBlock.Text = validation_error;
                MarkErrorHighlights(TransferCipherTextTextBox);
                return;
            }

            try
            {
                Attach_signature_from_last_packet_if_same_payload(packet);

                Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
                if (signature_settings.Sign_ciphertext)
                {
                    if (string.IsNullOrWhiteSpace(packet.Ephemeral_public_key_signature))
                    {
                        StatusTextBlock.Text = "В пакете отсутствует подпись отправителя. Проверьте, что отправитель передал пакет с подписью.";
                        MarkErrorHighlights(TransferCipherTextTextBox);
                        return;
                    }

                    if (signature_settings.Trusted_sender_long_term_public_keys is null ||
                        signature_settings.Trusted_sender_long_term_public_keys.Count == 0)
                    {
                        StatusTextBlock.Text = "Список доверенных публичных ключей отправителя пуст.";
                        MarkErrorHighlights(TransferCipherTextTextBox);
                        return;
                    }

                    if (!Digital_signature_store.Try_verify_cipher_package_signature_with_trusted_keys(
                            packet,
                            signature_settings.Trusted_sender_long_term_public_keys,
                            out string verification_error))
                    {
                        StatusTextBlock.Text = verification_error;
                        MarkErrorHighlights(TransferCipherTextTextBox);
                        return;
                    }
                }

                Stopwatch watch = Stopwatch.StartNew();
                string decrypted = _hybrid!.Decrypt(packet, _receiverPrivateKey);
                watch.Stop();

                SourceTextBox.Text = decrypted;
                DecryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {packet.Ciphertext.Length}";
                MarkPersistentHighlights(SourceTextBox);
                StatusTextBlock.Text = signature_settings.Sign_ciphertext
                    ? "Дешифрование выполнено. Текст записан в поле «Исходный текст». Цифровая подпись отправителя проверена."
                    : "Дешифрование выполнено. Текст записан в поле «Исходный текст».";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка дешифрования: {ex.Message}";
                MarkErrorHighlights(TransferCipherTextTextBox);
            }
        }

        private void MarkPersistentHighlights(params TextBox[] textBoxes)
        {
            // Подсвечивает поля с обновлёнными данными.
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

        private void MarkErrorHighlights(params TextBox[] textBoxes)
        {
            // Подсвечивает поля с ошибкой ввода/проверки.
            Brush errorBackground = new SolidColorBrush(Color.FromRgb(255, 241, 246));
            Brush errorBorder = new SolidColorBrush(Color.FromRgb(198, 56, 112));

            foreach (TextBox box in textBoxes)
            {
                box.Background = errorBackground;
                box.BorderBrush = errorBorder;
                box.BorderThickness = new Thickness(2);
                _highlightedTextBoxes.Add(box);
            }
        }

        private void ClearPersistentHighlights()
        {
            // Снимает подсветку с ранее отмеченных полей.
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

        private Hybrid_sender_context GetOrCreateManualSenderContext()
        {
            // Возвращает сохранённый контекст отправителя или создаёт новый.
            _manualSenderContext ??= _hybrid!.Create_sender_context();
            return _manualSenderContext;
        }

        private bool EnsureHybridReady()
        {
            // Лениво создаёт шифровальный модуль при первом использовании.
            if (!_warmUpCompleted)
            {
                StatusTextBlock.Text = _warmUpInProgress
                    ? "Подождите, идёт подготовка словарей шифрования..."
                    : "Словари шифрования ещё не готовы.";
                return false;
            }

            if (_hybrid is not null)
                return true;

            try
            {
                _wrapper = new Strategy_wrapper(new Factorial_strategy());
                _hybrid = new Hybrid_fns_cryptosystem(_wrapper);
                return true;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка инициализации шифровального модуля: {ex.Message}";
                return false;
            }
        }

        private bool EnsureRecipientLinksConfigured()
        {
            // Проверяет наличие хотя бы одной связи ключей получателя.
            if (Digital_signature_store.Has_configured_recipient_links())
                return true;

            StatusTextBlock.Text = LinksRequiredStatusMessage;
            return false;
        }

        private void SetCryptographyActionsEnabled(bool isEnabled)
        {
            // Управляет доступностью кнопок Encrypt/Decrypt на время прогрева словарей.
            EncryptButton.IsEnabled = isEnabled;
            DecryptButton.IsEnabled = isEnabled;
        }

        private bool IsAutoSenderKeyGenerationEnabled()
        {
            // Возвращает текущий режим автогенерации ключей отправителя.
            return AutoSenderKeyGenerationCheckBox.IsChecked != false;
        }

        private bool IsBuildJsonFileEnabled()
        {
            // Возвращает текущий режим сборки JSON-файла с данными передачи.
            return BuildJsonFileCheckBox.IsChecked == true;
        }

        private void DisposeManualSenderContext()
        {
            // Освобождает сохранённый контекст отправителя.
            _manualSenderContext?.Dispose();
            _manualSenderContext = null;
        }

        private void Attach_signature_from_last_packet_if_same_payload(Hybrid_cipher_package packet)
        {
            // Переносит подпись из последнего локально сформированного пакета,
            // если пользователь дешифрует эти же поля прямо в текущем окне.
            if (_lastEncryptedPacket is null)
                return;

            if (!string.IsNullOrWhiteSpace(packet.Ephemeral_public_key_signature))
                return;

            bool same_payload =
                string.Equals(packet.Ciphertext, _lastEncryptedPacket.Ciphertext, StringComparison.Ordinal) &&
                string.Equals(packet.Ephemeral_public_key, _lastEncryptedPacket.Ephemeral_public_key, StringComparison.Ordinal) &&
                string.Equals(packet.Encrypted_symmetric_key, _lastEncryptedPacket.Encrypted_symmetric_key, StringComparison.Ordinal);

            if (!same_payload)
                return;

            packet.Ephemeral_public_key_signature = _lastEncryptedPacket.Ephemeral_public_key_signature;
        }

        private static Hybrid_cipher_package Clone_packet(Hybrid_cipher_package source)
        {
            return new Hybrid_cipher_package
            {
                Ciphertext = source.Ciphertext,
                Encrypted_symmetric_key = source.Encrypted_symmetric_key,
                Ephemeral_public_key = source.Ephemeral_public_key,
                Ephemeral_public_key_signature = source.Ephemeral_public_key_signature,
                Block_plain_text_length = source.Block_plain_text_length,
                Curve_id = source.Curve_id
            };
        }

        private static bool Try_export_transfer_json(
            Hybrid_cipher_package packet,
            out string file_path,
            out string error_message)
        {
            file_path = string.Empty;
            error_message = string.Empty;

            try
            {
                Directory.CreateDirectory(TransferJsonDirectoryPath);

                string file_name = $"fns_transfer_{DateTime.Now:yyyyMMdd_HHmmss_fff}.json";
                file_path = Path.Combine(TransferJsonDirectoryPath, file_name);

                Transfer_json_package payload = new()
                {
                    Ephemeral_public_key = packet.Ephemeral_public_key,
                    Ephemeral_public_key_signature = packet.Ephemeral_public_key_signature,
                    Encrypted_symmetric_key = packet.Encrypted_symmetric_key,
                    Ciphertext = packet.Ciphertext
                };

                string json = JsonSerializer.Serialize(payload, TransferJsonSerializerOptions);
                File.WriteAllText(file_path, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                return true;
            }
            catch (Exception ex)
            {
                error_message = ex.Message;
                return false;
            }
        }

        private static void Try_ensure_transfer_json_directory_exists()
        {
            try
            {
                Directory.CreateDirectory(TransferJsonDirectoryPath);
            }
            catch
            {
                // Папка создаётся в best-effort режиме.
            }
        }

        private sealed class Transfer_json_package
        {
            [JsonPropertyOrder(1)]
            public string Ephemeral_public_key { get; set; } = string.Empty;

            [JsonPropertyOrder(2)]
            public string Ephemeral_public_key_signature { get; set; } = string.Empty;

            [JsonPropertyOrder(3)]
            public string Encrypted_symmetric_key { get; set; } = string.Empty;

            [JsonPropertyOrder(4)]
            public string Ciphertext { get; set; } = string.Empty;
        }

    }
}
