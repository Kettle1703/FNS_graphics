using System.Windows;

namespace FNS_graphics
{
    /// <summary>
    /// Application bootstrap.
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Определяет режим запуска: CLI-команда или стандартное окно.
            if (Cli_mode_runner.TryRun(e.Args, out int exit_code))
            {
                Shutdown(exit_code);
                return;
            }

            base.OnStartup(e);

            MainWindow window = new();
            MainWindow = window;
            window.Show();
        }
    }
}
