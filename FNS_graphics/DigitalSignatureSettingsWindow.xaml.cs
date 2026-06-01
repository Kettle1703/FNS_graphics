using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using FNS_rebuild;

namespace FNS_graphics
{
    public partial class DigitalSignatureSettingsWindow : Window
    {
        static readonly string Receiver_private_key_path = Path.Combine(AppContext.BaseDirectory, "receiver_ecdh_private.pk8.b64");
        static readonly string Receiver_public_key_path = Path.Combine(AppContext.BaseDirectory, "receiver_ecdh_public.spki.b64");

        bool settings_loaded_from_store;
        string active_recipient_runtime_key = string.Empty;

        readonly List<Recipient_link_view_item> recipient_links = [];

        public DigitalSignatureSettingsWindow()
        {
            InitializeComponent();
        }

        void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Load_own_receiver_public_key();

            Digital_signature_settings settings = Digital_signature_store.Get_settings_snapshot();
            SignCiphertextCheckBox.IsChecked = settings.Sign_ciphertext;

            recipient_links.Clear();
            foreach (Recipient_key_link_entry source in settings.Recipient_links)
                recipient_links.Add(Build_view_item_from_link(source));

            active_recipient_runtime_key = Find_runtime_key_by_link_id(settings.Active_recipient_link_id);
            if (active_recipient_runtime_key.Length == 0 && recipient_links.Count > 0)
                active_recipient_runtime_key = recipient_links[0].Runtime_key;

            GeneratedKeyTextBox.Text = string.Empty;
            Refresh_recipient_links_list();
            settings_loaded_from_store = true;
        }

        void Window_Closed(object? sender, EventArgs e)
        {
            if (!settings_loaded_from_store)
                return;

            List<Recipient_key_link_entry> links_to_save = [];
            foreach (Recipient_link_view_item view in recipient_links)
            {
                string link_id = Normalize_identifier(view.Link_id);
                if (link_id.Length == 0)
                    link_id = Guid.NewGuid().ToString("N");

                links_to_save.Add(new Recipient_key_link_entry
                {
                    Link_id = link_id,
                    Recipient_name = Normalize_identifier(view.Recipient_name),
                    Sender_signing_private_key_pkcs8 = Normalize_base64_text(view.Sender_signing_private_key_pkcs8),
                    Sender_signing_public_key_spki = Normalize_base64_text(view.Sender_signing_public_key_spki),
                    Trusted_sender_signing_public_key = Normalize_base64_text(view.Trusted_sender_signing_public_key),
                    Receiver_hybrid_public_key = Normalize_base64_text(view.Receiver_hybrid_public_key)
                });
            }

            string active_link_id_to_save = Find_link_id_by_runtime_key(active_recipient_runtime_key);
            if (active_link_id_to_save.Length == 0 && links_to_save.Count > 0)
                active_link_id_to_save = links_to_save[0].Link_id;

            Digital_signature_store.Save_settings(new Digital_signature_settings
            {
                Sign_ciphertext = SignCiphertextCheckBox.IsChecked != false,
                Recipient_links = links_to_save,
                Active_recipient_link_id = active_link_id_to_save
            });
        }

        void CreateRecipientLinkButton_Click(object sender, RoutedEventArgs e)
        {
            Recipient_key_link_entry generated = Digital_signature_store.Generate_recipient_key_link_entry();
            Recipient_link_view_item view_item = Build_view_item_from_link(generated);
            recipient_links.Add(view_item);

            if (active_recipient_runtime_key.Length == 0)
                active_recipient_runtime_key = view_item.Runtime_key;

            Refresh_recipient_links_list();
        }

        void SelectRecipientLinkButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string runtime_key })
                return;

            string normalized_runtime_key = Normalize_identifier(runtime_key);
            if (!Recipient_link_exists(normalized_runtime_key))
                return;

            active_recipient_runtime_key = normalized_runtime_key;
            Refresh_recipient_links_list();
        }

        void RegenerateRecipientLinkButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string runtime_key })
                return;

            string normalized_runtime_key = Normalize_identifier(runtime_key);
            Recipient_link_view_item? target = Find_recipient_link_by_runtime_key(normalized_runtime_key);
            if (target is null)
                return;

            Recipient_key_link_entry regenerated = Digital_signature_store.Generate_recipient_key_link_entry(target.Recipient_name);
            target.Sender_signing_private_key_pkcs8 = regenerated.Sender_signing_private_key_pkcs8;
            target.Sender_signing_public_key_spki = regenerated.Sender_signing_public_key_spki;
            target.Trusted_sender_signing_public_key = regenerated.Trusted_sender_signing_public_key;
            target.Receiver_hybrid_public_key = regenerated.Receiver_hybrid_public_key;

            Refresh_recipient_links_list();
        }

        void RemoveRecipientLinkButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string runtime_key })
                return;

            string normalized_runtime_key = Normalize_identifier(runtime_key);
            recipient_links.RemoveAll(value => string.Equals(value.Runtime_key, normalized_runtime_key, StringComparison.Ordinal));

            if (!Recipient_link_exists(active_recipient_runtime_key))
                active_recipient_runtime_key = recipient_links.Count > 0 ? recipient_links[0].Runtime_key : string.Empty;

            Refresh_recipient_links_list();
        }

        void GenerateSenderSigningPublicKeyButton_Click(object sender, RoutedEventArgs e)
        {
            GeneratedKeyTextBox.Text = Digital_signature_store.Generate_sender_signing_public_key_spki_base64();
        }

        void GenerateReceiverHybridPublicKeyButton_Click(object sender, RoutedEventArgs e)
        {
            GeneratedKeyTextBox.Text = Digital_signature_store.Generate_receiver_hybrid_public_key_spki_base64();
        }

        void Refresh_recipient_links_list()
        {
            for (int i = 0; i < recipient_links.Count; i++)
            {
                Recipient_link_view_item view = recipient_links[i];
                bool is_active = string.Equals(view.Runtime_key, active_recipient_runtime_key, StringComparison.Ordinal);

                view.Active_label = is_active
                    ? "Активная связь"
                    : "Связь";
                view.Can_select = !is_active;
            }

            if (recipient_links.Count == 0)
                ActiveRecipientInfoTextBlock.Text = "Активная связь: не выбрана";
            else
                ActiveRecipientInfoTextBlock.Text = $"Активная связь: {Find_recipient_name_by_runtime_key(active_recipient_runtime_key)}";

            RecipientLinksListBox.ItemsSource = null;
            RecipientLinksListBox.ItemsSource = recipient_links;
        }

        Recipient_link_view_item Build_view_item_from_link(Recipient_key_link_entry source)
        {
            string private_key = Normalize_base64_text(source.Sender_signing_private_key_pkcs8);
            string sender_public_key = Normalize_base64_text(source.Sender_signing_public_key_spki);
            if (sender_public_key.Length == 0 &&
                Digital_signature_store.Try_get_sender_signing_public_key_from_private(
                    private_key,
                    out string sender_public_key_from_private,
                    out _))
            {
                sender_public_key = sender_public_key_from_private;
            }

            return new Recipient_link_view_item
            {
                Runtime_key = Guid.NewGuid().ToString("N"),
                Link_id = Normalize_identifier(source.Link_id),
                Recipient_name = Normalize_identifier(source.Recipient_name),
                Sender_signing_private_key_pkcs8 = private_key,
                Sender_signing_public_key_spki = sender_public_key,
                Trusted_sender_signing_public_key = Normalize_base64_text(source.Trusted_sender_signing_public_key),
                Receiver_hybrid_public_key = Normalize_base64_text(source.Receiver_hybrid_public_key)
            };
        }

        void Load_own_receiver_public_key()
        {
            try
            {
                using ECDiffieHellman receiver_private = Receiver_key_store.LoadOrCreate(
                    Receiver_private_key_path,
                    Receiver_public_key_path);

                OwnReceiverPublicKeyTextBox.Text = Base64_url_codec.Encode(receiver_private.ExportSubjectPublicKeyInfo());
            }
            catch
            {
                OwnReceiverPublicKeyTextBox.Text = "<не удалось загрузить ключ>";
            }
        }

        Recipient_link_view_item? Find_recipient_link_by_runtime_key(string runtime_key)
        {
            foreach (Recipient_link_view_item view in recipient_links)
            {
                if (string.Equals(view.Runtime_key, runtime_key, StringComparison.Ordinal))
                    return view;
            }

            return null;
        }

        bool Recipient_link_exists(string runtime_key)
        {
            return Find_recipient_link_by_runtime_key(runtime_key) is not null;
        }

        string Find_runtime_key_by_link_id(string link_id)
        {
            string normalized_link_id = Normalize_identifier(link_id);
            if (normalized_link_id.Length == 0)
                return string.Empty;

            foreach (Recipient_link_view_item view in recipient_links)
            {
                if (string.Equals(view.Link_id, normalized_link_id, StringComparison.Ordinal))
                    return view.Runtime_key;
            }

            return string.Empty;
        }

        string Find_link_id_by_runtime_key(string runtime_key)
        {
            Recipient_link_view_item? view = Find_recipient_link_by_runtime_key(runtime_key);
            return view is null ? string.Empty : Normalize_identifier(view.Link_id);
        }

        string Find_recipient_name_by_runtime_key(string runtime_key)
        {
            Recipient_link_view_item? view = Find_recipient_link_by_runtime_key(runtime_key);
            if (view is null)
                return "не выбрана";

            string name = Normalize_identifier(view.Recipient_name);
            return name.Length == 0 ? "без имени" : name;
        }

        static string Normalize_identifier(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            return value.Trim();
        }

        static string Normalize_base64_text(string? value)
        {
            return Base64_url_codec.Canonicalize_if_possible(value);
        }

        sealed class Recipient_link_view_item
        {
            public string Runtime_key { get; init; } = string.Empty;
            public string Link_id { get; set; } = string.Empty;
            public string Recipient_name { get; set; } = string.Empty;
            public string Sender_signing_private_key_pkcs8 { get; set; } = string.Empty;
            public string Sender_signing_public_key_spki { get; set; } = string.Empty;
            public string Trusted_sender_signing_public_key { get; set; } = string.Empty;
            public string Receiver_hybrid_public_key { get; set; } = string.Empty;
            public string Active_label { get; set; } = string.Empty;
            public bool Can_select { get; set; }
        }
    }
}
