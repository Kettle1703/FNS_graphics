using System;
using System.Windows;

namespace FNS_graphics
{
    public partial class SwitchesWindow : Window
    {
        bool loaded;

        public SwitchesWindow()
        {
            InitializeComponent();
        }

        void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Ui_toggle_settings ui_toggle_settings = Ui_toggle_store.Get_snapshot();
            BuildJsonFileCheckBox.IsChecked = ui_toggle_settings.Build_json_file;
            ApplyReedSolomonForJsonCheckBox.IsChecked = ui_toggle_settings.Apply_reed_solomon_for_json;
            AutoSenderKeyGenerationCheckBox.IsChecked = ui_toggle_settings.Auto_sender_key_generation;

            Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
            SignCiphertextCheckBox.IsChecked = signature_settings.Sign_ciphertext;

            loaded = true;
        }

        void Window_Closed(object? sender, EventArgs e)
        {
            if (!loaded)
                return;

            Ui_toggle_store.Save(new Ui_toggle_settings
            {
                Build_json_file = BuildJsonFileCheckBox.IsChecked == true,
                Apply_reed_solomon_for_json = ApplyReedSolomonForJsonCheckBox.IsChecked == true,
                Auto_sender_key_generation = AutoSenderKeyGenerationCheckBox.IsChecked != false
            });

            Digital_signature_settings signature_settings = Digital_signature_store.Get_settings_snapshot();
            signature_settings.Sign_ciphertext = SignCiphertextCheckBox.IsChecked != false;
            Digital_signature_store.Save_settings(signature_settings);
        }

        void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}

