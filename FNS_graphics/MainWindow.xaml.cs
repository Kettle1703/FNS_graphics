using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Win32;
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

        private static readonly JsonSerializerOptions TransferJsonSerializerOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        private static readonly JsonSerializerOptions TransferPayloadJsonSerializerOptions = new()
        {
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        private const int DefaultBlockLength = 1096;
        private const int TransferPacketDataShards = 8;
        private const int TransferPacketParityShards = 4;

        private Strategy_wrapper? _wrapper;
        private Hybrid_fns_cryptosystem? _hybrid;
        private ECDiffieHellman _receiverPrivateKey;
        private byte[] _receiverPublicKeySpki;
        private readonly List<TextBox> _highlightedTextBoxes = [];
        private Hybrid_sender_context? _manualSenderContext;
        private Hybrid_cipher_package? _lastEncryptedPacket;
        private string _activeRecipientReceiverPublicKeySpki = string.Empty;
        private bool _lastPacketLoadedFromJsonFile;
        private bool _lastPacketRecoveredFromReedSolomon;
        private bool _warmUpCompleted;
        private bool _warmUpInProgress;
        private const string AutoPlaceholder = "<заполняется автоматически>";
        private const string LinksRequiredStatusMessage = "Для шифрования или дешифрования необходимо настроить связи ключей.";

        public MainWindow()
        {
            // Инициализирует окно и базовые поля интерфейса.
            InitializeComponent();
            Load_ui_toggle_snapshot_into_controls();

            _receiverPrivateKey = Receiver_key_store.LoadOrCreateDefault();
            _receiverPublicKeySpki = _receiverPrivateKey.ExportSubjectPublicKeyInfo();

            SharedSenderPublicKeyTextBox.Text = AutoPlaceholder;
            SharedSenderPublicKeySignatureTextBox.Text = string.Empty;
            SharedReceiverPublicKeyFingerprintTextBox.Text = AutoPlaceholder;
            ActiveRecipientLinkTextBlock.Text = "Связь: не выбрана";
            SharedKeyDerivationSaltTextBox.Text = AutoPlaceholder;
            TransferCipherTextTextBox.Text = string.Empty;

            EncryptMetricsTextBlock.Text = "Ядро: - | Обёртка: - | Длина: -";
            DecryptMetricsTextBlock.Text = "Ядро: - | Обёртка: - | Длина: -";
            StatusTextBlock.Text = "Подготовка словарей шифрования...";
            SetCryptographyActionsEnabled(false);
            Digital_signature_settings initial_signature_settings = Digital_signature_store.Get_settings_snapshot();
            ApplySignatureControlsState(initial_signature_settings.Sign_ciphertext);
            if (!initial_signature_settings.Sign_ciphertext)
                SharedReceiverPublicKeyFingerprintTextBox.Text = "<подпись отключена>";
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
                _ = Try_apply_active_recipient_link_to_main_form(report_validation_error: false);
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
            Apply_auto_sender_key_generation_mode(show_status_message: true);
        }

        private void SwitchesWindowButton_Click(object sender, RoutedEventArgs e)
        {
            // Открывает окно со всеми переключателями режима.
            bool previous_auto_sender_mode = IsAutoSenderKeyGenerationEnabled();

            SwitchesWindow switches_window = new()
            {
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };

            switches_window.ShowDialog();

            Load_ui_toggle_snapshot_into_controls();
            bool auto_sender_mode_changed = IsAutoSenderKeyGenerationEnabled() != previous_auto_sender_mode;
            Apply_auto_sender_key_generation_mode(show_status_message: auto_sender_mode_changed);
            ReloadReceiverKey();
            _ = Try_apply_active_recipient_link_to_main_form(report_validation_error: false);
        }

        private void ReloadReceiverKey()
        {
            ECDiffieHellman previous_key = _receiverPrivateKey;
            _receiverPrivateKey = Receiver_key_store.LoadOrCreateDefault();
            _receiverPublicKeySpki = _receiverPrivateKey.ExportSubjectPublicKeyInfo();
            previous_key.Dispose();
        }

        private void DigitalSignatureSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            // Открывает окно настроек цифровой подписи.
            DigitalSignatureSettingsWindow settingsWindow = new()
            {
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };

            settingsWindow.Closed += DigitalSignatureSettingsWindow_Closed;
            settingsWindow.Show();
        }

        private void DigitalSignatureSettingsWindow_Closed(object? sender, EventArgs e)
        {
            // После закрытия окна настроек подтягивает ключи активной связи в основную форму.
            bool previous_auto_sender_mode = IsAutoSenderKeyGenerationEnabled();
            Load_ui_toggle_snapshot_into_controls();
            bool auto_sender_mode_changed = IsAutoSenderKeyGenerationEnabled() != previous_auto_sender_mode;
            Apply_auto_sender_key_generation_mode(show_status_message: auto_sender_mode_changed);
            _ = Try_apply_active_recipient_link_to_main_form(report_validation_error: false);
        }

        private void SelectDecryptJsonFileButton_Click(object sender, RoutedEventArgs e)
        {
            // Загружает JSON-пакет передачи и заполняет поля для дешифрования.
            ClearPersistentHighlights();

            OpenFileDialog dialog = new()
            {
                Title = "Выбор JSON-пакета для дешифрования",
                Filter = "JSON файлы (*.json)|*.json|Все файлы (*.*)|*.*",
                CheckFileExists = true,
                Multiselect = false
            };

            string transfer_json_directory_path = Get_transfer_json_directory_path();
            if (Directory.Exists(transfer_json_directory_path))
                dialog.InitialDirectory = transfer_json_directory_path;

            bool? result = dialog.ShowDialog(this);
            if (result != true)
                return;

            if (!Try_load_transfer_json_packet(
                    dialog.FileName,
                    out Hybrid_cipher_package packet,
                    out bool loaded_from_reed_solomon_packet,
                    out string load_error))
            {
                StatusTextBlock.Text = load_error;
                MarkErrorHighlights(TransferCipherTextTextBox);
                return;
            }

            _lastEncryptedPacket = Clone_packet(packet);
            _lastPacketLoadedFromJsonFile = true;
            _lastPacketRecoveredFromReedSolomon = loaded_from_reed_solomon_packet;
            TransferCipherTextTextBox.Text = packet.Ciphertext;
            DecryptMetricsTextBlock.Text = Build_length_metrics_text(packet.Ciphertext.Length);
            SharedSenderPublicKeyTextBox.Text = packet.Ephemeral_public_key;
            SharedSenderPublicKeySignatureTextBox.Text = packet.Ephemeral_public_key_signature;
            SharedKeyDerivationSaltTextBox.Text = packet.Key_derivation_salt;

            if (SharedReceiverPublicKeyFingerprintTextBox.IsEnabled &&
                !string.IsNullOrWhiteSpace(packet.Sender_signing_key_fingerprint))
            {
                SharedReceiverPublicKeyFingerprintTextBox.Text = packet.Sender_signing_key_fingerprint;
            }

            if (SharedReceiverPublicKeyFingerprintTextBox.IsEnabled)
            {
                MarkPersistentHighlights(
                    TransferCipherTextTextBox,
                    SharedSenderPublicKeyTextBox,
                    SharedSenderPublicKeySignatureTextBox,
                    SharedKeyDerivationSaltTextBox,
                    SharedReceiverPublicKeyFingerprintTextBox);
            }
            else
            {
                MarkPersistentHighlights(
                    TransferCipherTextTextBox,
                    SharedSenderPublicKeyTextBox,
                    SharedKeyDerivationSaltTextBox);
            }

            StatusTextBlock.Text = Build_status_text(status =>
            {
                status.AppendLine($"JSON-пакет загружен: {dialog.FileName}");
                status.AppendLine(Build_reed_solomon_decode_status_line(loaded_from_reed_solomon_packet));
            });
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            // Выполняет шифрование и заполняет поля передачи.
            ClearPersistentHighlights();
            if (!EnsureHybridReady())
                return;

            if (!EnsureRecipientLinksConfigured())
                return;

            if (!Try_apply_active_recipient_link_to_main_form(report_validation_error: true))
                return;

            if (!Window_input_validation.TryBuildEncryptRequest(
                    SourceTextBox.Text,
                    _activeRecipientReceiverPublicKeySpki,
                    _receiverPublicKeySpki,
                    DefaultBlockLength,
                    GetSelectedEncryptionCore(),
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

                Crypto_operation_timing timing = new();
                timing.Start_wrapper();
                Hybrid_cipher_package packet = _hybrid!.Encrypt(
                    request.Source_text,
                    request.Receiver_public_spki,
                    request.Options,
                    senderContext,
                    timing);

                Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
                ApplySignatureControlsState(signature_settings.Sign_ciphertext);
                if (signature_settings.Sign_ciphertext)
                {
                    if (!Digital_signature_store.Try_get_sender_signing_key_fingerprint(
                            signature_settings.Active_sender_signing_public_key,
                            out string sender_signing_key_fingerprint,
                            out string fingerprint_error))
                    {
                        StatusTextBlock.Text = fingerprint_error;
                        return;
                    }

                    packet.Sender_signing_key_fingerprint = sender_signing_key_fingerprint;

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
                    packet.Sender_signing_key_fingerprint = string.Empty;
                    packet.Ephemeral_public_key_signature = string.Empty;
                }

                bool build_json_file = IsBuildJsonFileEnabled();
                bool apply_reed_solomon = false;
                bool json_export_success = false;
                string json_file_path = string.Empty;
                string json_export_error = string.Empty;
                if (build_json_file)
                {
                    apply_reed_solomon = IsReedSolomonEnabledForJson();
                    json_export_success = Try_export_transfer_json(
                        packet,
                        apply_reed_solomon,
                        out json_file_path,
                        out json_export_error);
                }

                timing.Stop_wrapper();

                _lastEncryptedPacket = Clone_packet(packet);
                _lastPacketLoadedFromJsonFile = false;
                _lastPacketRecoveredFromReedSolomon = false;
                TransferCipherTextTextBox.Text = packet.Ciphertext;
                SharedSenderPublicKeyTextBox.Text = packet.Ephemeral_public_key;
                SharedSenderPublicKeySignatureTextBox.Text = packet.Ephemeral_public_key_signature;
                SharedKeyDerivationSaltTextBox.Text = packet.Key_derivation_salt;

                EncryptMetricsTextBlock.Text = Build_operation_metrics_text(timing, request.Source_text.Length);
                DecryptMetricsTextBlock.Text = Build_length_metrics_text(packet.Ciphertext.Length);
                if (signature_settings.Sign_ciphertext)
                {
                    MarkPersistentHighlights(
                        TransferCipherTextTextBox,
                        SharedSenderPublicKeyTextBox,
                        SharedSenderPublicKeySignatureTextBox,
                        SharedReceiverPublicKeyFingerprintTextBox,
                        SharedKeyDerivationSaltTextBox);
                }
                else
                {
                    MarkPersistentHighlights(
                        TransferCipherTextTextBox,
                        SharedSenderPublicKeyTextBox,
                        SharedKeyDerivationSaltTextBox);
                }

                StatusTextBlock.Text = Build_status_text(status =>
                {
                    status.AppendLine(signature_settings.Sign_ciphertext
                        ? "Шифрование выполнено. Пакет подписан долгосрочным ключом отправителя."
                        : "Шифрование выполнено. Данные для передачи заполнены в общем блоке.");

                    if (!build_json_file)
                        return;

                    if (json_export_success)
                    {
                        status.AppendLine($"Расположение созданного файла: {json_file_path}");
                        status.AppendLine(Build_reed_solomon_encode_status_line(apply_reed_solomon));
                    }
                    else
                    {
                        status.AppendLine($"JSON файл не создан: {json_export_error}");
                        status.AppendLine("Код Рида-Соломона: не наложен, так как JSON-файл передачи не создан.");
                    }
                });
            }
            catch (CryptographicException)
            {
                StatusTextBlock.Text = "Ошибка шифрования: не удалось сформировать криптографический пакет. Проверьте корректность ключей активной связи.";
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
                    SharedKeyDerivationSaltTextBox.Text,
                    SharedSenderPublicKeySignatureTextBox.Text,
                    DefaultBlockLength,
                    GetSelectedEncryptionCore(),
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
                Crypto_operation_timing timing = new();
                timing.Start_wrapper();
                Attach_signature_from_last_packet_if_same_payload(packet);
                string matched_recipient_name = string.Empty;

                Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
                if (signature_settings.Sign_ciphertext)
                {
                    if (string.IsNullOrWhiteSpace(packet.Ephemeral_public_key_signature))
                    {
                        StatusTextBlock.Text = "В пакете отсутствует подпись отправителя. Проверьте, что отправитель передал пакет с подписью.";
                        MarkErrorHighlights(TransferCipherTextTextBox);
                        return;
                    }

                    if (!Digital_signature_store.Try_verify_cipher_package_signature_and_select_recipient_link(
                            packet,
                            out Recipient_key_link_entry matched_link,
                            out string verification_error))
                    {
                        StatusTextBlock.Text = verification_error;
                        MarkErrorHighlights(TransferCipherTextTextBox);
                        return;
                    }

                    matched_recipient_name = string.IsNullOrWhiteSpace(matched_link.Recipient_name)
                        ? "без имени"
                        : matched_link.Recipient_name;
                    _ = Try_apply_active_recipient_link_to_main_form(report_validation_error: false);
                }

                string decrypted = _hybrid!.Decrypt(packet, _receiverPrivateKey, timing);
                timing.Stop_wrapper();

                SourceTextBox.Text = decrypted;
                EncryptMetricsTextBlock.Text = Build_length_metrics_text(decrypted.Length);
                DecryptMetricsTextBlock.Text = Build_operation_metrics_text(timing, packet.Ciphertext.Length);
                MarkPersistentHighlights(SourceTextBox);
                StatusTextBlock.Text = Build_status_text(status =>
                {
                    status.AppendLine(signature_settings.Sign_ciphertext
                        ? $"Дешифрование выполнено. Текст записан в поле «Исходный текст». Цифровая подпись отправителя проверена. Активная связь: {matched_recipient_name}."
                        : "Дешифрование выполнено. Текст записан в поле «Исходный текст».");

                    if (_lastPacketLoadedFromJsonFile)
                        status.AppendLine(Build_reed_solomon_decode_status_line(_lastPacketRecoveredFromReedSolomon));
                });
            }
            catch (CryptographicException)
            {
                StatusTextBlock.Text = Build_decrypt_cryptography_error_message();
                MarkErrorHighlights(TransferCipherTextTextBox);
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
            Digital_signature_settings settings_snapshot = Digital_signature_store.Get_settings_snapshot();
            if (!settings_snapshot.Sign_ciphertext)
                return true;

            if (Digital_signature_store.Has_configured_recipient_links())
                return true;

            StatusTextBlock.Text = LinksRequiredStatusMessage;
            return false;
        }

        private bool Try_apply_active_recipient_link_to_main_form(bool report_validation_error)
        {
            // Подтягивает ключ получателя из активной связи и валидирует формат ключа.
            if (!Digital_signature_store.Try_get_active_recipient_link_snapshot(
                    out Recipient_key_link_entry active_link,
                    out string link_error))
            {
                Digital_signature_settings settings_snapshot = Digital_signature_store.Get_settings_snapshot();
                ApplySignatureControlsState(settings_snapshot.Sign_ciphertext);
                ActiveRecipientLinkTextBlock.Text = "Связь: не выбрана";
                SharedReceiverPublicKeyFingerprintTextBox.Text = settings_snapshot.Sign_ciphertext
                    ? AutoPlaceholder
                    : "<подпись отключена>";
                _activeRecipientReceiverPublicKeySpki = string.Empty;

                if (!settings_snapshot.Sign_ciphertext)
                    return true;

                if (report_validation_error)
                    StatusTextBlock.Text = link_error;
                return false;
            }

            Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
            ApplySignatureControlsState(signature_settings.Sign_ciphertext);

            string receiver_public_key = active_link.Receiver_hybrid_public_key?.Trim() ?? string.Empty;
            if (!Digital_signature_store.Try_validate_receiver_hybrid_public_key(receiver_public_key, out string validation_error))
            {
                string recipient_name_with_error = string.IsNullOrWhiteSpace(active_link.Recipient_name)
                    ? "без имени"
                    : active_link.Recipient_name.Trim();
                ActiveRecipientLinkTextBlock.Text = $"Связь: {recipient_name_with_error}";
                SharedReceiverPublicKeyFingerprintTextBox.Text = "<некорректный ключ>";
                _activeRecipientReceiverPublicKeySpki = string.Empty;
                if (report_validation_error)
                    StatusTextBlock.Text = validation_error;
                return false;
            }

            string recipient_name = string.IsNullOrWhiteSpace(active_link.Recipient_name)
                ? "без имени"
                : active_link.Recipient_name.Trim();

            if (!signature_settings.Sign_ciphertext)
            {
                ActiveRecipientLinkTextBlock.Text = $"Связь: {recipient_name}";
                SharedReceiverPublicKeyFingerprintTextBox.Text = "<подпись отключена>";
                // В режиме без подписи шифруем на локальный ключ получателя,
                // чтобы пользователь гарантированно мог расшифровать собственный пакет.
                _activeRecipientReceiverPublicKeySpki = string.Empty;
                return true;
            }

            if (!Digital_signature_store.Try_get_sender_signing_key_fingerprint(
                    signature_settings.Active_sender_signing_public_key,
                    out string key_fingerprint,
                    out string fingerprint_error))
            {
                ActiveRecipientLinkTextBlock.Text = $"Связь: {recipient_name}";
                SharedReceiverPublicKeyFingerprintTextBox.Text = "<ошибка слепка>";
                _activeRecipientReceiverPublicKeySpki = receiver_public_key;
                if (report_validation_error)
                    StatusTextBlock.Text = fingerprint_error;
                return false;
            }

            ActiveRecipientLinkTextBlock.Text = $"Связь: {recipient_name}";
            SharedReceiverPublicKeyFingerprintTextBox.Text = key_fingerprint;
            _activeRecipientReceiverPublicKeySpki = receiver_public_key;
            return true;
        }

        private static string Build_decrypt_cryptography_error_message()
        {
            return "Ошибка дешифрования: не удалось восстановить симметрический материал и проверить целостность пакета. " +
                   "Обычно это означает, что пакет зашифрован не на ваш публичный ключ получателя или данные пакета повреждены.";
        }

        private static string Build_reed_solomon_encode_status_line(bool applied)
        {
            return applied
                ? $"Код Рида-Соломона: наложен ({TransferPacketDataShards} data + {TransferPacketParityShards} parity шардов)."
                : "Код Рида-Соломона: отключён переключателем, JSON сохранён без внешней RS-обёртки.";
        }

        private static string Build_reed_solomon_decode_status_line(bool restored_from_reed_solomon_packet)
        {
            return restored_from_reed_solomon_packet
                ? "Код Рида-Соломона: снят и проверен при чтении JSON-пакета."
                : "Код Рида-Соломона: во входном JSON не обнаружен (загружена полезная нагрузка без внешнего RS-пакета).";
        }

        private static string Build_operation_metrics_text(Crypto_operation_timing timing, int length)
        {
            return $"Ядро: {timing.Core_elapsed.TotalMilliseconds:F2} мс | " +
                   $"Обёртка: {timing.Wrapper_elapsed.TotalMilliseconds:F2} мс | " +
                   $"Длина: {length}";
        }

        private static string Build_length_metrics_text(int length)
        {
            return $"Ядро: - | Обёртка: - | Длина: {length}";
        }

        private static string Build_status_text(Action<StringBuilder> compose_status)
        {
            StringBuilder status = new();
            compose_status(status);
            return status.ToString().TrimEnd('\r', '\n');
        }

        private void ApplySignatureControlsState(bool isSignatureEnabled)
        {
            // Управляет состоянием полей цифровой подписи на основной форме.
            SharedSenderPublicKeySignatureTextBox.IsEnabled = isSignatureEnabled;
            SharedReceiverPublicKeyFingerprintTextBox.IsEnabled = isSignatureEnabled;
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

        private bool IsReedSolomonEnabledForJson()
        {
            // Возвращает режим применения внешней RS-обёртки для JSON-файлов.
            return DisableReedSolomonForJsonCheckBox.IsChecked == true;
        }

        private void Load_ui_toggle_snapshot_into_controls()
        {
            // Подтягивает состояние интерфейсных переключателей из общего in-memory хранилища.
            Ui_toggle_settings snapshot = Ui_toggle_store.Get_snapshot();
            BuildJsonFileCheckBox.IsChecked = snapshot.Build_json_file;
            DisableReedSolomonForJsonCheckBox.IsChecked = snapshot.Apply_reed_solomon_for_json;
            AutoSenderKeyGenerationCheckBox.IsChecked = snapshot.Auto_sender_key_generation;
        }

        private void Apply_auto_sender_key_generation_mode(bool show_status_message)
        {
            if (!IsLoaded)
                return;

            if (IsAutoSenderKeyGenerationEnabled())
            {
                DisposeManualSenderContext();
                if (show_status_message)
                    StatusTextBlock.Text = "Автогенерация новых ключей отправителя включена.";
                return;
            }

            if (_hybrid is not null)
                _manualSenderContext ??= _hybrid.Create_sender_context();

            if (show_status_message)
                StatusTextBlock.Text = "Автогенерация отключена. Ключ отправителя и публичная соль восстановления симметричного ключа будут постоянными.";
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

            bool same_payload =
                string.Equals(packet.Ciphertext, _lastEncryptedPacket.Ciphertext, StringComparison.Ordinal) &&
                string.Equals(packet.Ephemeral_public_key, _lastEncryptedPacket.Ephemeral_public_key, StringComparison.Ordinal) &&
                string.Equals(packet.Key_derivation_salt, _lastEncryptedPacket.Key_derivation_salt, StringComparison.Ordinal);

            if (!same_payload)
                return;

            if (string.IsNullOrWhiteSpace(packet.Ephemeral_public_key_signature))
                packet.Ephemeral_public_key_signature = _lastEncryptedPacket.Ephemeral_public_key_signature;

            if (string.IsNullOrWhiteSpace(packet.Sender_signing_key_fingerprint))
                packet.Sender_signing_key_fingerprint = _lastEncryptedPacket.Sender_signing_key_fingerprint;

            packet.Encryption_core = _lastEncryptedPacket.Encryption_core;
            packet.Round_cipher_enabled = Is_factorial_round_cipher_enabled(packet.Encryption_core);
        }

        private static Hybrid_cipher_package Clone_packet(Hybrid_cipher_package source)
        {
            return new Hybrid_cipher_package
            {
                Ciphertext = source.Ciphertext,
                Key_derivation_salt = source.Key_derivation_salt,
                Ephemeral_public_key = source.Ephemeral_public_key,
                Ephemeral_public_key_signature = source.Ephemeral_public_key_signature,
                Sender_signing_key_fingerprint = source.Sender_signing_key_fingerprint,
                Block_plain_text_length = source.Block_plain_text_length,
                Encryption_core = source.Encryption_core,
                Round_cipher_enabled = Is_factorial_round_cipher_enabled(source.Encryption_core),
                Curve_id = source.Curve_id
            };
        }

        private static bool Try_load_transfer_json_packet(
            string file_path,
            out Hybrid_cipher_package packet,
            out bool loaded_from_reed_solomon_packet,
            out string error_message)
        {
            packet = null!;
            loaded_from_reed_solomon_packet = false;
            error_message = string.Empty;

            try
            {
                string json = File.ReadAllText(file_path, Encoding.UTF8);
                if (Try_parse_transfer_payload_json(json, out packet, out _))
                    return true;

                if (!Try_parse_transmission_packet_json(json, out Transmission_packet transmission_packet, out string transmission_packet_error))
                {
                    error_message = transmission_packet_error;
                    return false;
                }

                Transmission_error_protection transmission_protection = new();
                string recovered_payload_json;
                try
                {
                    recovered_payload_json = transmission_protection.Recover(transmission_packet);
                }
                catch (Exception ex)
                {
                    error_message = $"Ошибка восстановления Reed-Solomon: {ex.Message}";
                    return false;
                }

                if (!Try_parse_transfer_payload_json(recovered_payload_json, out packet, out string payload_error))
                {
                    error_message = $"После восстановления Reed-Solomon структура полезной нагрузки некорректна: {payload_error}";
                    return false;
                }

                loaded_from_reed_solomon_packet = true;
                return true;
            }
            catch (Exception ex)
            {
                error_message = $"Ошибка чтения JSON-пакета: {ex.Message}";
                return false;
            }
        }

        private static bool Try_parse_transfer_payload_json(
            string json,
            out Hybrid_cipher_package packet,
            out string error_message)
        {
            packet = null!;
            error_message = string.Empty;

            Transfer_json_package? payload = JsonSerializer.Deserialize<Transfer_json_package>(json);
            if (payload is null)
            {
                error_message = "JSON-пакет пуст или имеет некорректную структуру.";
                return false;
            }

            string ciphertext = payload.Ciphertext?.Trim() ?? string.Empty;
            string ephemeral_public_key = Base64_url_codec.Canonicalize_if_possible(payload.Ephemeral_public_key);
            string signature = Base64_url_codec.Canonicalize_if_possible(payload.Ephemeral_public_key_signature);
            string sender_fingerprint = payload.Sender_signing_key_fingerprint?.Trim() ?? string.Empty;
            string key_derivation_salt = Base64_url_codec.Canonicalize_if_possible(payload.Key_derivation_salt);

            if (ciphertext.Length == 0)
            {
                error_message = "В JSON-пакете отсутствует поле Ciphertext.";
                return false;
            }

            if (!Try_decode_base64(ephemeral_public_key, out _))
            {
                error_message = "В JSON-пакете поле Ephemeral_public_key должно быть корректным Base64/Base64URL.";
                return false;
            }

            if (!Try_decode_base64(key_derivation_salt, out _))
            {
                error_message = "В JSON-пакете поле Key_derivation_salt должно быть корректным Base64/Base64URL.";
                return false;
            }

            if (signature.Length > 0 && !Try_decode_base64(signature, out _))
            {
                error_message = "В JSON-пакете поле Ephemeral_public_key_signature должно быть корректным Base64/Base64URL.";
                return false;
            }

            if (sender_fingerprint.Length > 0 && !Is_valid_key_fingerprint(sender_fingerprint))
            {
                error_message = "В JSON-пакете поле Sender_signing_key_fingerprint должно быть HEX SHA-256.";
                return false;
            }

            Encryption_core_kind encryption_core = Encryption_core_catalog.From_storage_id(payload.Encryption_core);
            packet = new Hybrid_cipher_package
            {
                Ciphertext = ciphertext,
                Ephemeral_public_key = ephemeral_public_key,
                Ephemeral_public_key_signature = signature,
                Sender_signing_key_fingerprint = sender_fingerprint,
                Key_derivation_salt = key_derivation_salt,
                Block_plain_text_length = DefaultBlockLength,
                Encryption_core = encryption_core,
                Round_cipher_enabled = Is_factorial_round_cipher_enabled(encryption_core),
                Curve_id = Hybrid_fns_cryptosystem.Curve_id_nist_p256
            };
            return true;
        }

        private static bool Is_factorial_round_cipher_enabled(Encryption_core_kind encryption_core)
        {
            return encryption_core == Encryption_core_kind.Factorial;
        }

        private static bool Try_parse_transmission_packet_json(
            string json,
            out Transmission_packet packet,
            out string error_message)
        {
            packet = null!;
            error_message = string.Empty;

            try
            {
                Transmission_packet? parsed = JsonSerializer.Deserialize<Transmission_packet>(json);
                if (parsed is null)
                {
                    error_message = "JSON-пакет не распознан как пакет передачи.";
                    return false;
                }

                if (parsed.Data_shards < 1 || parsed.Parity_shards < 1)
                {
                    error_message = "JSON-пакет не распознан как пакет Reed-Solomon: параметры шардов некорректны.";
                    return false;
                }

                int total_shards = parsed.Data_shards + parsed.Parity_shards;
                if (parsed.Shards_base64url is null || parsed.Shard_crc32 is null)
                {
                    error_message = "JSON-пакет Reed-Solomon повреждён: отсутствуют шардовые данные.";
                    return false;
                }

                if (parsed.Shards_base64url.Count != total_shards || parsed.Shard_crc32.Count != total_shards)
                {
                    error_message = "JSON-пакет Reed-Solomon повреждён: некорректное количество шардов.";
                    return false;
                }

                packet = parsed;
                return true;
            }
            catch (Exception ex)
            {
                error_message = $"JSON-пакет не распознан как пакет Reed-Solomon: {ex.Message}";
                return false;
            }
        }

        private static bool Try_decode_base64(string encoded, out byte[] bytes)
        {
            return Base64_url_codec.Try_decode(encoded, out bytes);
        }

        private static bool Is_valid_key_fingerprint(string value)
        {
            string normalized = (value ?? string.Empty).Trim();
            if (normalized.Length != 64)
                return false;

            for (int i = 0; i < normalized.Length; i++)
            {
                char ch = normalized[i];
                bool is_digit = ch >= '0' && ch <= '9';
                bool is_hex_lower = ch >= 'a' && ch <= 'f';
                bool is_hex_upper = ch >= 'A' && ch <= 'F';
                if (!is_digit && !is_hex_lower && !is_hex_upper)
                    return false;
            }

            return true;
        }

        private static bool Try_export_transfer_json(
            Hybrid_cipher_package packet,
            bool apply_reed_solomon,
            out string file_path,
            out string error_message)
        {
            file_path = string.Empty;
            error_message = string.Empty;

            try
            {
                string transfer_json_directory_path = Get_transfer_json_directory_path();
                Directory.CreateDirectory(transfer_json_directory_path);

                string file_name = $"fns_transfer_{DateTime.Now:yyyyMMdd_HHmmss_fff}.json";
                file_path = Path.Combine(transfer_json_directory_path, file_name);

                Transfer_json_package payload = new()
                {
                    Ephemeral_public_key = packet.Ephemeral_public_key,
                    Ephemeral_public_key_signature = packet.Ephemeral_public_key_signature,
                    Sender_signing_key_fingerprint = packet.Sender_signing_key_fingerprint,
                    Key_derivation_salt = packet.Key_derivation_salt,
                    Round_cipher_enabled = packet.Round_cipher_enabled,
                    Encryption_core = Encryption_core_catalog.To_storage_id(packet.Encryption_core),
                    Ciphertext = packet.Ciphertext
                };

                string payload_json = JsonSerializer.Serialize(payload, TransferPayloadJsonSerializerOptions);
                string json;

                if (apply_reed_solomon)
                {
                    Transmission_error_protection transmission_protection = new();
                    Transmission_packet transmission_packet = transmission_protection.Protect(
                        payload_json,
                        TransferPacketDataShards,
                        TransferPacketParityShards);

                    json = JsonSerializer.Serialize(transmission_packet, TransferJsonSerializerOptions);
                }
                else
                {
                    json = JsonSerializer.Serialize(payload, TransferJsonSerializerOptions);
                }

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
                Directory.CreateDirectory(Get_transfer_json_directory_path());
            }
            catch
            {
                // Папка создаётся в best-effort режиме.
            }
        }

        private static string Get_transfer_json_directory_path()
        {
            return Ui_toggle_store.Get_snapshot().Json_transfer_directory_path;
        }

        private static Encryption_core_kind GetSelectedEncryptionCore()
        {
            return Ui_toggle_store.Get_snapshot().Encryption_core;
        }

        private sealed class Transfer_json_package
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

    }
}
