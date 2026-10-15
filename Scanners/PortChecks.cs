using System.Net;
using System.Net.NetworkInformation;

namespace snaktools
{
    internal static class PortChecks
    {
        // Puertos que suelen ser riesgosos si están expuestos (también los usa NetworkChecks).
        public static readonly Dictionary<int, (string Servicio, int Gravedad)> RiskyPorts = new Dictionary<int, (string Servicio, int Gravedad)>
        {
            { 21,    ("FTP (sin cifrar)", Severity.Medio) },
            { 23,    ("Telnet (sin cifrar)", Severity.Alto) },
            { 135,   ("RPC", Severity.Medio) },
            { 139,   ("NetBIOS", Severity.Medio) },
            { 445,   ("SMB (compartir archivos)", Severity.Alto) },
            { 3306,  ("MySQL", Severity.Medio) },
            { 3389,  ("Escritorio remoto (RDP)", Severity.Alto) },
            { 5432,  ("PostgreSQL", Severity.Medio) },
            { 5900,  ("VNC", Severity.Alto) },
            { 27017, ("MongoDB", Severity.Medio) }
        };

        public static void Run(ScanContext ctx)
        {
            IPEndPoint[] escuchando = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            var reportados = new HashSet<int>();

            foreach (IPEndPoint punto in escuchando)
            {
                // Solo cuentan los puertos accesibles desde la red (no los que escuchan solo en localhost).
                if (!IPAddress.IsLoopback(punto.Address)
                    && reportados.Add(punto.Port)
                    && RiskyPorts.TryGetValue(punto.Port, out var info))
                {
                    ctx.Add($"Puerto {punto.Port} abierto",
                        $"{info.Servicio} está aceptando conexiones desde la red. Si no lo usas, ciérralo o bloquéalo en el firewall.",
                        info.Gravedad);
                }
            }
        }
    }
}