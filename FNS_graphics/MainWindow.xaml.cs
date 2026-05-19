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

        private Strategy_wrapper? _wrapper;
        private Hybrid_fns_cryptosystem? _hybrid;
        private readonly ECDiffieHellman _receiverPrivateKey;
        private readonly byte[] _receiverPublicKeySpki;
        private readonly List<TextBox> _highlightedTextBoxes = [];
        private Hybrid_sender_context? _manualSenderContext;
        private const string AutoPlaceholder = "<заполняется автоматически>";

        public MainWindow()
        {
            // Инициализирует окно и базовые поля интерфейса.
            InitializeComponent();

            _receiverPrivateKey = Receiver_key_store.LoadOrCreate(ReceiverPrivateKeyPath, ReceiverPublicKeyPath);
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

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Загружает словари шифрования после отображения окна.
            try
            {
                Factorial_strategy.Warm_up();
                StatusTextBlock.Text = "Словари шифрования загружены.";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка загрузки словарей: {ex.Message}";
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

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            // Выполняет шифрование и заполняет поля передачи.
            ClearPersistentHighlights();
            if (!EnsureHybridReady())
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
                watch.Stop();

                TransferCipherTextTextBox.Text = packet.Ciphertext;
                SharedSenderPublicKeyTextBox.Text = packet.Ephemeral_public_key;
                SharedSessionKeyTextBox.Text = packet.Encrypted_symmetric_key;

                EncryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {request.Source_text.Length}";
                MarkPersistentHighlights(
                    TransferCipherTextTextBox,
                    SharedSenderPublicKeyTextBox,
                    SharedSessionKeyTextBox);

                StatusTextBlock.Text = "Шифрование выполнено. Данные для передачи заполнены в общем блоке.";
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

            if (!Window_input_validation.TryBuildDecryptPacket(
                    TransferCipherTextTextBox.Text,
                    SharedSenderPublicKeyTextBox.Text,
                    SharedSessionKeyTextBox.Text,
                    DefaultBlockLength,
                    AutoPlaceholder,
                    out Hybrid_cipher_package packet,
                    out string validation_error))
            {
                StatusTextBlock.Text = validation_error;
                return;
            }

            try
            {
                Stopwatch watch = Stopwatch.StartNew();
                string decrypted = _hybrid!.Decrypt(packet, _receiverPrivateKey);
                watch.Stop();

                SourceTextBox.Text = decrypted;
                DecryptMetricsTextBlock.Text = $"Время: {watch.Elapsed.TotalMilliseconds:F2} мс | Длина: {packet.Ciphertext.Length}";
                MarkPersistentHighlights(SourceTextBox);
                StatusTextBlock.Text = "Дешифрование выполнено. Текст записан в поле «Исходный текст».";
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Ошибка дешифрования: {ex.Message}";
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

        private bool IsAutoSenderKeyGenerationEnabled()
        {
            // Возвращает текущий режим автогенерации ключей отправителя.
            return AutoSenderKeyGenerationCheckBox.IsChecked != false;
        }

        private void DisposeManualSenderContext()
        {
            // Освобождает сохранённый контекст отправителя.
            _manualSenderContext?.Dispose();
            _manualSenderContext = null;
        }

    }
}
