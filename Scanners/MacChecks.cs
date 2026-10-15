namespace snaktools
{
    internal static class MacChecks
    {
        public static void Run(ScanContext ctx)
        {
            string firewall = CommandRunner.Run("/usr/libexec/ApplicationFirewall/socketfilterfw", new[] { "--getglobalstate" });
            if (firewall.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("Firewall de macOS desactivado",
                    "Actívalo en Ajustes del Sistema > Red > Firewall.",
                    Severity.Alto);
            }

            string sip = CommandRunner.Run("csrutil", new[] { "status" });
            if (sip.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("SIP (System Integrity Protection) desactivado",
                    "SIP protege los archivos del sistema. Se reactiva desde el modo de recuperación.",
                    Severity.Alto);
            }

            string fileVault = CommandRunner.Run("fdesetup", new[] { "status" });
            if (fileVault.Contains("FileVault is Off", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("FileVault desactivado",
                    "El disco no está cifrado. Actívalo en Ajustes del Sistema > Privacidad y seguridad.",
                    Severity.Medio);
            }
        }
    }
}