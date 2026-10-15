using System.Diagnostics;
using System.Text;

namespace snaktools
{
    internal static class CommandRunner
    {
        // Ejecuta un comando y devuelve su salida. Si falla o no existe, devuelve "".
        public static string Run(string file, string[] args, int timeoutMs = 20000)
        {
            try
            {
                var psi = new ProcessStartInfo(file)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                foreach (string arg in args)
                {
                    psi.ArgumentList.Add(arg);
                }

                using Process? proceso = Process.Start(psi);
                if (proceso == null)
                {
                    return "";
                }

                Task<string> salida = proceso.StandardOutput.ReadToEndAsync();
                Task<string> error = proceso.StandardError.ReadToEndAsync();

                if (!proceso.WaitForExit(timeoutMs))
                {
                    try { proceso.Kill(true); } catch (Exception) { }
                    return "";
                }

                proceso.WaitForExit();
                return salida.Result.Trim().TrimStart('\uFEFF').Trim();
            }
            catch (Exception)
            {
                return "";
            }
        }

        // Ejecuta un comando de PowerShell. La salida se fuerza a UTF-8 para que
        // los nombres con tildes o eñes (por ejemplo, el de una red WiFi) lleguen bien.
        public static string PowerShell(string script, int timeoutMs = 60000)
        {
            string completo = "try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }; " + script;
            return Run("powershell.exe", new[] { "-NoProfile", "-NonInteractive", "-Command", completo }, timeoutMs);
        }
    }
}
