using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace snaktools
{
    internal static class WindowsChecks
    {
        [SupportedOSPlatform("windows")]
        public static void Run(ScanContext ctx)
        {
            // Firewall
            string firewall = CommandRunner.PowerShell(
                "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } | ForEach-Object { $_.Name }) -join ', '");
            if (!string.IsNullOrWhiteSpace(firewall))
            {
                ctx.Add("Firewall de Windows desactivado",
                    $"Perfiles sin protección: {firewall}. Actívalo para bloquear conexiones no deseadas.",
                    Severity.Alto);
            }

            // Antivirus (Microsoft Defender)
            string tiempoReal = CommandRunner.PowerShell("(Get-MpComputerStatus).RealTimeProtectionEnabled");
            if (tiempoReal.Equals("False", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("Protección en tiempo real desactivada",
                    "Microsoft Defender no está protegiendo en tiempo real. Si usas otro antivirus, puede ser normal.",
                    Severity.Alto);
            }

            string edadFirmas = CommandRunner.PowerShell("(Get-MpComputerStatus).AntivirusSignatureAge");
            if (int.TryParse(edadFirmas, out int dias) && dias > 7)
            {
                ctx.Add("Definiciones de antivirus desactualizadas",
                    $"Las definiciones de Defender tienen {dias} días. Actualízalas desde Seguridad de Windows.",
                    Severity.Medio);
            }

            // SMBv1 (requiere administrador)
            string smb1 = CommandRunner.PowerShell("(Get-SmbServerConfiguration).EnableSMB1Protocol");
            if (smb1.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("SMBv1 habilitado",
                    "SMBv1 es un protocolo antiguo y vulnerable (usado por ataques como WannaCry). Desactívalo.",
                    Severity.Alto);
            }
            else if (string.IsNullOrWhiteSpace(smb1) && !Environment.IsPrivilegedProcess)
            {
                ctx.Notes.Add("SMBv1 no se pudo comprobar porque requiere permisos de administrador.");
            }

            // Escritorio remoto
            object? rdp = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", null);
            if (rdp is int valorRdp && valorRdp == 0)
            {
                ctx.Add("Escritorio remoto habilitado",
                    "Este equipo acepta conexiones por Escritorio remoto. Si no lo usas, desactívalo.",
                    Severity.Medio);
            }

            // Control de cuentas de usuario (UAC)
            object? uac = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", null);
            if (uac is int valorUac && valorUac == 0)
            {
                ctx.Add("Control de cuentas de usuario (UAC) desactivado",
                    "Sin UAC, cualquier programa puede ejecutarse con permisos elevados sin avisarte.",
                    Severity.Alto);
            }

            // Cuenta de invitado
            string invitado = CommandRunner.PowerShell("(Get-LocalUser -Name 'Guest').Enabled");
            if (invitado.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Add("Cuenta de invitado habilitada",
                    "La cuenta Guest está activa. Desactívala si no la necesitas.",
                    Severity.Medio);
            }

            // Parches recientes
            string fecha = CommandRunner.PowerShell(
                "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')");
            if (DateTime.TryParseExact(fecha, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime ultimoParche)
                && (DateTime.Now - ultimoParche).TotalDays > 60)
            {
                ctx.Add("Sin parches de seguridad recientes",
                    $"La última actualización instalada es del {ultimoParche:dd/MM/yyyy}. Revisa Windows Update.",
                    Severity.Medio);
            }
        }
    }
}