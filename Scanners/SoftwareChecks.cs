using System.Runtime.Versioning;
using Microsoft.Win32;

namespace snaktools
{
    internal static class SoftwareChecks
    {
        // Software que se sabe obsoleto o sin soporte.
        private static readonly (string Patron, string Motivo, int Gravedad)[] SoftwareRiesgoso =
        {
            ("Flash Player", "Adobe Flash Player está descontinuado desde 2020 y ya no recibe parches de seguridad.", Severity.Alto),
            ("Silverlight", "Microsoft Silverlight llegó al fin de soporte en 2021.", Severity.Medio),
            ("Python 2.", "Python 2 está sin soporte desde 2020.", Severity.Medio)
        };

        public static void Run(ScanContext ctx)
        {
            if (!LoadPrograms(ctx))
            {
                return;
            }

            foreach ((string nombre, string version) in ctx.Programs)
            {
                foreach (var regla in SoftwareRiesgoso)
                {
                    if (nombre.Contains(regla.Patron, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Add($"Software obsoleto: {nombre}", regla.Motivo, regla.Gravedad);
                    }
                }

                if (nombre.StartsWith("WinRAR", StringComparison.OrdinalIgnoreCase)
                    && Version.TryParse(version, out Version? v)
                    && v < new Version(6, 23))
                {
                    ctx.Add($"WinRAR desactualizado ({version})",
                        "Las versiones anteriores a 6.23 tienen una vulnerabilidad de ejecución de código (CVE-2023-38831). Actualiza WinRAR.",
                        Severity.Alto);
                }
            }

            if (!ctx.Config.RevisarCve)
            {
                ctx.Notes.Add("La revisión de programas usa una lista corta de software obsoleto; la consulta de CVE está desactivada en config.json.");
            }
        }

        // Carga la lista de programas instalados en ctx.Programs (solo Windows).
        // Devuelve false si no se pudo.
        public static bool LoadPrograms(ScanContext ctx)
        {
            if (ctx.Programs.Count > 0)
            {
                return true;
            }

            if (!OperatingSystem.IsWindows())
            {
                ctx.Note("La revisión de programas instalados solo está disponible en Windows por ahora.");
                return false;
            }

            ctx.Programs = GetInstalledPrograms();
            ctx.InstalledPrograms = ctx.Programs.Count;
            return true;
        }

        [SupportedOSPlatform("windows")]
        private static List<(string Nombre, string Version)> GetInstalledPrograms()
        {
            var programas = new List<(string Nombre, string Version)>();

            string[] rutas =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (string ruta in rutas)
            {
                using RegistryKey? clave = Registry.LocalMachine.OpenSubKey(ruta);

                if (clave != null)
                {
                    foreach (string nombreSub in clave.GetSubKeyNames())
                    {
                        using RegistryKey? sub = clave.OpenSubKey(nombreSub);
                        string? nombre = sub?.GetValue("DisplayName") as string;
                        string? version = sub?.GetValue("DisplayVersion") as string;

                        if (!string.IsNullOrWhiteSpace(nombre))
                        {
                            programas.Add((nombre, version ?? ""));
                        }
                    }
                }
            }

            return programas.Distinct().ToList();
        }
    }
}
