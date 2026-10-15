using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace snaktools
{
    internal static class NetworkChecks
    {
        public static void Run(ScanContext ctx)
        {
            (IPAddress? miIp, IPAddress? puertaEnlace) = GetNetworkInfo();

            if (miIp == null)
            {
                ctx.Notes.Add("No se encontró una conexión de red activa.");
                return;
            }

            ctx.Gateway = puertaEnlace;

            string[] octetos = miIp.ToString().Split('.');
            string prefijo = $"{octetos[0]}.{octetos[1]}.{octetos[2]}.";

            List<string> hosts = DiscoverHosts(prefijo, miIp.ToString()).GetAwaiter().GetResult();
            Dictionary<string, string> tablaArp = GetArpTable();

            ctx.Devices = hosts
                .Select(ip => new NetworkDevice { Ip = ip, Mac = tablaArp.TryGetValue(ip, out string? mac) ? mac : "" })
                .ToList();

            ctx.Notes.Add($"Se escaneó la subred {prefijo}0/24 y se encontraron {ctx.Devices.Count} dispositivos que responden a ping. Los que bloquean ping pueden no aparecer.");

            // Puertos riesgosos en cada dispositivo (los puertos salen de config.json)
            int[] puertos = ctx.Config.PuertosRed;
            int timeout = ctx.Config.TimeoutPuertoMs;

            var pruebas = new List<Task<(string Ip, int Puerto, bool Abierto)>>();
            foreach (string ip in hosts)
            {
                foreach (int puerto in puertos)
                {
                    pruebas.Add(ProbarPuerto(ip, puerto, timeout));
                }
            }

            var resultados = Task.WhenAll(pruebas).GetAwaiter().GetResult();

            foreach (var r in resultados)
            {
                if (r.Abierto)
                {
                    var info = PortChecks.RiskyPorts.TryGetValue(r.Puerto, out var conocido)
                        ? conocido
                        : ("Servicio sin identificar", Severity.Bajo);

                    bool esRouter = puertaEnlace != null && r.Ip == puertaEnlace.ToString();
                    string etiqueta = esRouter ? " (router)" : "";

                    ctx.Add($"Puerto {r.Puerto} abierto en {r.Ip}{etiqueta}",
                        $"{info.Item1} accesible desde la red local. Revisa si ese dispositivo necesita tenerlo abierto.",
                        info.Item2);
                }
            }

            // Dispositivos desconocidos
            if (ctx.Devices.Count > 0)
            {
                if (!File.Exists(AppPaths.TrustedFile))
                {
                    SaveTrusted(ctx.Devices);
                    ctx.Notes.Add($"Primer escaneo de red: los {ctx.Devices.Count} dispositivos encontrados se guardaron como confiables en 'dispositivos_confiables.txt'. Verifica que todos sean tuyos.");
                }
                else
                {
                    var confiables = new HashSet<string>(File.ReadAllLines(AppPaths.TrustedFile).Select(l => l.Trim()));

                    foreach (NetworkDevice d in ctx.Devices)
                    {
                        if (!confiables.Contains(d.Id))
                        {
                            string mac = string.IsNullOrEmpty(d.Mac) ? "no disponible" : d.Mac;
                            ctx.Add($"Dispositivo nuevo en la red: {d.Ip}",
                                $"No estaba en tu lista de dispositivos confiables (MAC: {mac}). Si no lo reconoces, cambia la contraseña del WiFi.",
                                Severity.Medio);
                        }
                    }
                }
            }
        }

        public static (IPAddress? Ip, IPAddress? Gateway) GetNetworkInfo()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up
                    && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback
                    && ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                {
                    IPInterfaceProperties props = ni.GetIPProperties();

                    IPAddress? gw = props.GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                        ?.Address;

                    IPAddress? ip = props.UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                        ?.Address;

                    if (gw != null && ip != null)
                    {
                        return (ip, gw);
                    }
                }
            }

            return (null, null);
        }

        public static void SaveTrusted(IEnumerable<NetworkDevice> dispositivos)
        {
            var ids = new HashSet<string>();

            if (File.Exists(AppPaths.TrustedFile))
            {
                foreach (string linea in File.ReadAllLines(AppPaths.TrustedFile))
                {
                    if (!string.IsNullOrWhiteSpace(linea))
                    {
                        ids.Add(linea.Trim());
                    }
                }
            }

            foreach (NetworkDevice d in dispositivos)
            {
                ids.Add(d.Id);
            }

            File.WriteAllLines(AppPaths.TrustedFile, ids);
        }

        private static async Task<List<string>> DiscoverHosts(string prefijo, string miIp)
        {
            Func<int, Task<string?>> probar = async i =>
            {
                string ip = prefijo + i;

                if (ip == miIp)
                {
                    return null;
                }

                try
                {
                    using var ping = new Ping();
                    PingReply respuesta = await ping.SendPingAsync(ip, 700);
                    return respuesta.Status == IPStatus.Success ? ip : null;
                }
                catch (Exception)
                {
                    return null;
                }
            };

            string?[] resultados = await Task.WhenAll(Enumerable.Range(1, 254).Select(probar));

            return resultados.Where(ip => ip != null).Select(ip => ip!).ToList();
        }

        private static Dictionary<string, string> GetArpTable()
        {
            var tabla = new Dictionary<string, string>();
            string salida = CommandRunner.Run("arp", new[] { "-a" });

            const string patron = @"(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})";

            foreach (Match m in Regex.Matches(salida, patron))
            {
                tabla[m.Groups[1].Value] = NormalizarMac(m.Groups[2].Value);
            }

            return tabla;
        }

        private static string NormalizarMac(string mac)
        {
            return string.Join(":", Regex.Split(mac, "[:-]").Select(p => p.PadLeft(2, '0').ToLower()));
        }

        private static async Task<(string Ip, int Puerto, bool Abierto)> ProbarPuerto(string ip, int puerto, int timeoutMs)
        {
            bool abierto = await PuertoAbierto(ip, puerto, timeoutMs);
            return (ip, puerto, abierto);
        }

        private static async Task<bool> PuertoAbierto(string ip, int puerto, int timeoutMs)
        {
            try
            {
                using var cliente = new TcpClient();
                using var cts = new CancellationTokenSource(timeoutMs);
                await cliente.ConnectAsync(IPAddress.Parse(ip), puerto, cts.Token);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}