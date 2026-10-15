using System.Diagnostics;
using System.Text;

namespace snaktools
{
    class Notification
    {
        public void Show(string message)
        {
            ShowClickable(message, null, false);
        }

        // Muestra una notificación. Si se pasa una ruta, al hacer clic en la notificación se abre ese archivo (el reporte).
        public void ShowClickable(string message, string? openOnClick, bool wait)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    string limpio = message.Replace("'", "''");
                    string ruta = (openOnClick ?? "").Replace("'", "''");

                    string script =
                        "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; " +
                        "$path = '" + ruta + "'; " +
                        "$n = New-Object System.Windows.Forms.NotifyIcon; " +
                        "$n.Icon = [System.Drawing.SystemIcons]::Shield; $n.Visible = $true; " +
                        "$n.BalloonTipTitle = 'snaktools'; $n.BalloonTipText = '" + limpio + "'; " +
                        "$n.add_BalloonTipClicked({ if ($path -ne '') { Start-Process -FilePath $path }; [System.Windows.Forms.Application]::Exit() }); " +
                        "$n.add_BalloonTipClosed({ [System.Windows.Forms.Application]::Exit() }); " +
                        "$t = New-Object System.Windows.Forms.Timer; $t.Interval = 30000; $t.add_Tick({ [System.Windows.Forms.Application]::Exit() }); $t.Start(); " +
                        "$n.ShowBalloonTip(15000); [System.Windows.Forms.Application]::Run(); $n.Dispose()";

                    string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

                    using Process? p = Process.Start(new ProcessStartInfo("powershell.exe",
                        "-NoProfile -WindowStyle Hidden -EncodedCommand " + encoded)
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });

                    if (wait && p != null)
                    {
                        p.WaitForExit(40000);
                    }
                }
                else if (OperatingSystem.IsLinux())
                {
                    var psi = new ProcessStartInfo("notify-send") { UseShellExecute = false, CreateNoWindow = true };
                    psi.ArgumentList.Add("snaktools");
                    psi.ArgumentList.Add(message);
                    Process.Start(psi);
                }
                else if (OperatingSystem.IsMacOS())
                {
                    string limpio = message.Replace("\\", "\\\\").Replace("\"", "\\\"");
                    var psi = new ProcessStartInfo("osascript") { UseShellExecute = false, CreateNoWindow = true };
                    psi.ArgumentList.Add("-e");
                    psi.ArgumentList.Add("display notification \"" + limpio + "\" with title \"snaktools\"");
                    Process.Start(psi);
                }
            }
            catch (Exception)
            {
                Console.WriteLine("(No se pudo mostrar la notificación del sistema.)");
            }
        }
    }
}
