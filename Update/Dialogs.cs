using System.Text;

namespace snaktools
{
    // Ventanas sencillas de Windows con botones (en otros sistemas se usa la consola).
    internal static class Dialogs
    {
        // Devuelve true si el usuario elige "Actualizar ahora".
        public static bool AskUpdate(string versionNueva, string notas)
        {
            string texto = $"Hay una nueva versión de snaktools disponible: {versionNueva}\n(tienes la {AppInfo.Version}).\n\n" +
                           (notas == "" ? "" : "Novedades:\n" + notas + "\n\n") +
                           "¿Quieres actualizar ahora?";

            if (OperatingSystem.IsWindows())
            {
                string? respuesta = ShowWindowsDialog(texto);

                if (respuesta != null)
                {
                    return respuesta == "ahora";
                }
            }

            Console.WriteLine();
            Console.WriteLine(texto.Replace("\n", Environment.NewLine));
            return ConsoleUi.AskYesNo("¿Actualizar ahora? (n = más tarde)");
        }

        private static string? ShowWindowsDialog(string texto)
        {
            string limpio = texto.Replace("'", "''");
            string script =
                "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; " +
                "[System.Windows.Forms.Application]::EnableVisualStyles(); " +
                "$f = New-Object System.Windows.Forms.Form; $f.Text = 'snaktools - Actualización disponible'; " +
                "$f.Size = New-Object System.Drawing.Size(480,320); $f.StartPosition = 'CenterScreen'; $f.TopMost = $true; " +
                "$f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; " +
                "$l = New-Object System.Windows.Forms.Label; $l.Text = '" + limpio + "'; $l.Location = New-Object System.Drawing.Point(20,20); $l.Size = New-Object System.Drawing.Size(430,200); " +
                "$b1 = New-Object System.Windows.Forms.Button; $b1.Text = 'Actualizar ahora'; $b1.Size = New-Object System.Drawing.Size(140,32); $b1.Location = New-Object System.Drawing.Point(110,235); $b1.DialogResult = 'Yes'; " +
                "$b2 = New-Object System.Windows.Forms.Button; $b2.Text = 'Más tarde'; $b2.Size = New-Object System.Drawing.Size(110,32); $b2.Location = New-Object System.Drawing.Point(265,235); $b2.DialogResult = 'No'; " +
                "$f.Controls.Add($l); $f.Controls.Add($b1); $f.Controls.Add($b2); $f.AcceptButton = $b1; $f.CancelButton = $b2; " +
                "$r = $f.ShowDialog(); if ($r -eq 'Yes') { 'ahora' } else { 'despues' }";

            string codificado = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string salida = CommandRunner.Run("powershell.exe", new[] { "-NoProfile", "-EncodedCommand", codificado }, 10 * 60 * 1000);

            if (salida.Contains("ahora")) return "ahora";
            if (salida.Contains("despues")) return "despues";
            return null;
        }
    }
}
