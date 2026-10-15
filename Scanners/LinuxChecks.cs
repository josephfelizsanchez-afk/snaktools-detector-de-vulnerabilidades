using System.Text.RegularExpressions;

namespace snaktools
{
    internal static class LinuxChecks
    {
        public static void Run(ScanContext ctx)
        {
            const string sshConfig = "/etc/ssh/sshd_config";

            if (File.Exists(sshConfig))
            {
                foreach (string linea in File.ReadAllLines(sshConfig))
                {
                    if (Regex.IsMatch(linea, @"^\s*PermitRootLogin\s+yes\b", RegexOptions.IgnoreCase))
                    {
                        ctx.Add("Login de root por SSH habilitado",
                            "PermitRootLogin está en 'yes' en sshd_config. Usa un usuario normal con sudo.",
                            Severity.Alto);
                    }
                }
            }

            string ufw = CommandRunner.Run("ufw", new[] { "status" });
            if (ufw.Contains("inactive", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("Firewall (ufw) inactivo",
                    "ufw está instalado pero desactivado. Actívalo con 'sudo ufw enable'.",
                    Severity.Medio);
            }
            else if (string.IsNullOrWhiteSpace(ufw) && !Environment.IsPrivilegedProcess)
            {
                ctx.Notes.Add("No se pudo comprobar ufw (no está instalado o requiere permisos de root).");
            }

            string apt = CommandRunner.Run("apt", new[] { "list", "--upgradable" });
            int pendientes = apt.Split('\n').Count(l => l.Contains("upgradable", StringComparison.OrdinalIgnoreCase));
            if (pendientes > 0)
            {
                ctx.Add("Actualizaciones pendientes",
                    $"Hay {pendientes} paquetes con actualización disponible. Ejecuta 'sudo apt update && sudo apt upgrade'.",
                    Severity.Medio);
            }
        }
    }
}