using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace snaktools
{
    enum ScanType
    {
        Equipo,
        Red
    }

    internal class Program
    {
        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            var scanner = new VulnerabilityScanner();
            bool salir = false;

            while (!salir)
            {
                Console.Clear();
                Console.WriteLine("Bienvenido al programa de detección de vulnerabilidades snaktools.");
                Console.WriteLine("Seleccione una opción:");
                Console.WriteLine("1. Escanear el equipo en busca de vulnerabilidades.");
                Console.WriteLine("2. Escanear la red en busca de vulnerabilidades.");
                Console.WriteLine("3. Salir del programa.");
                Console.Write("Opción: ");

                string opcion = (Console.ReadLine() ?? "").Trim();

                switch (opcion)
                {
                    case "1":
                        await EjecutarEscaneo(scanner, ScanType.Equipo);
                        break;

                    case "2":
                        if (ConfirmarEscaneoRed())
                        {
                            await EjecutarEscaneo(scanner, ScanType.Red);
                        }
                        break;

                    case "3":
                        salir = true;
                        break;

                    default:
                        Console.WriteLine("Opción inválida.");
                        break;
                }

                if (!salir)
                {
                    Console.Write("Presione Enter para volver al menú...");
                    Console.ReadLine();
                }
            }
        }

        static bool ConfirmarEscaneoRed()
        {
            Console.WriteLine();
            Console.WriteLine("El escaneo de red prueba los dispositivos de tu red local (ping y algunos puertos comunes).");
            Console.WriteLine("Úsalo solo en una red que sea tuya o en la que tengas permiso para hacerlo.");
            return PreguntarSiNo("¿Desea continuar?");
        }

        static bool PreguntarSiNo(string pregunta)
        {
            bool respondio = false;
            bool resultado = false;

            while (!respondio)
            {
                Console.Write($"{pregunta} (s/n): ");
                string respuesta = (Console.ReadLine() ?? "").Trim().ToLower();

                if (respuesta == "s" || respuesta == "si" || respuesta == "sí")
                {
                    resultado = true;
                    respondio = true;
                }
                else if (respuesta == "n" || respuesta == "no")
                {
                    respondio = true;
                }
                else
                {
                    Console.WriteLine("Responda 's' o 'n'.");
                }
            }

            return resultado;
        }

        static async Task EjecutarEscaneo(VulnerabilityScanner scanner, ScanType tipo)
        {
            Console.WriteLine();

            if (!Environment.IsPrivilegedProcess)
            {
                Console.WriteLine("Aviso: no estás ejecutando como administrador/root. Algunas revisiones pueden quedar incompletas.");
            }

            Console.Write(tipo == ScanType.Equipo ? "Escaneando el equipo" : "Escaneando la red (puede tardar un poco)");

            try
            {
                // El escaneo corre en segundo plano mientras la consola muestra el progreso.
                Task tareaEscaneo = Task.Run(() => scanner.Scan(tipo));

                while (!tareaEscaneo.IsCompleted)
                {
                    Console.Write(".");
                    await Task.Delay(500);
                }

                await tareaEscaneo;
                Console.WriteLine();

                scanner.GenerateReport();
                scanner.NotifyUser();
                MostrarResultados(scanner);

                if (scanner.Vulnerabilities.Count > 0)
                {
                    Console.WriteLine();
                    if (PreguntarSiNo("¿Desea ver las opciones para tomar medidas?"))
                    {
                        scanner.TakeActionOnVulnerabilities();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine($"El escaneo falló: {ex.Message}");
            }
        }

        static void MostrarResultados(VulnerabilityScanner scanner)
        {
            Console.WriteLine();
            Console.WriteLine($"Escaneo completado en {scanner.ScanDuration} s. Vulnerabilidades encontradas: {scanner.Vulnerabilities.Count}.");
            Console.WriteLine();

            foreach (Vulnerability v in scanner.Vulnerabilities)
            {
                Console.WriteLine($"[{VulnerabilityScanner.GetSeverityName(v.SeverityLevel)}] {v.Name}");
                Console.WriteLine($"    {v.Description}");
            }

            if (scanner.Notes.Count > 0)
            {
                Console.WriteLine();
                foreach (string nota in scanner.Notes)
                {
                    Console.WriteLine($"Nota: {nota}");
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Reporte guardado en: {scanner.ReportPath}");
        }
    }

    class Vulnerability
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public int SeverityLevel { get; set; } // 1 = Bajo, 2 = Medio, 3 = Alto
    }

    class Report
    {
        public DateTime ScanDate { get; set; }
        public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public int TotalVulnerabilities { get; set; }
        public int TotalSeverityLevel { get; set; }
    }

    class NetworkDevice
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";
        public string Id => string.IsNullOrEmpty(Mac) ? Ip : Mac;
    }

    class Notification
    {
        public void Show(string message)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    string script =
                        "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; " +
                        "$n = New-Object System.Windows.Forms.NotifyIcon; " +
                        "$n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; " +
                        $"$n.ShowBalloonTip(5000, 'snaktools', '{message.Replace("'", "''")}', [System.Windows.Forms.ToolTipIcon]::Info); " +
                        "Start-Sleep -Seconds 6; $n.Dispose()";

                    string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

                    Process.Start(new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -WindowStyle Hidden -EncodedCommand {encoded}")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
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
                    psi.ArgumentList.Add($"display notification \"{limpio}\" with title \"snaktools\"");
                    Process.Start(psi);
                }
            }
            catch (Exception)
            {
                Console.WriteLine("(No se pudo mostrar la notificación del sistema.)");
            }
        }
    }

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
                return salida.Result.Trim();
            }
            catch (Exception)
            {
                return "";
            }
        }

        public static string PowerShell(string script)
        {
            return Run("powershell.exe", new[] { "-NoProfile", "-NonInteractive", "-Command", script }, 60000);
        }
    }

    class VulnerabilityScanner
    {
        private const string ReportFile = "reporte_vulnerabilidades.txt";
        private const string TrustedFile = "dispositivos_confiables.txt";

        private int scanDuration = 0;            // duración del último escaneo en segundos
        private int vulnerabilitiesFound = 0;    // vulnerabilidades del último escaneo
        private int severityLevel = 0;           // gravedad más alta del último escaneo
        private int totalVulnerabilities = 0;    // acumulado de todos los escaneos
        private int totalSeverityLevel = 0;      // acumulado de gravedad de todos los escaneos
        private int totalScanDuration = 0;       // acumulado de segundos de escaneo
        private int totalScans = 0;              // escaneos realizados

        private ScanType lastScanType = ScanType.Equipo;
        private DateTime lastScanDate = DateTime.Now;
        private int installedProgramsCount = 0;
        private IPAddress? gateway = null;
        private List<NetworkDevice> lastDevices = new List<NetworkDevice>();

        public List<Vulnerability> Vulnerabilities { get; private set; } = new List<Vulnerability>();
        public List<string> Notes { get; private set; } = new List<string>();
        public string ReportPath { get; private set; } = "";
        public int ScanDuration => scanDuration;

        // Puertos que suelen ser riesgosos si están expuestos.
        private static readonly Dictionary<int, (string Servicio, int Gravedad)> PuertosRiesgosos = new Dictionary<int, (string, int)>
        {
            { 21,    ("FTP (sin cifrar)", 2) },
            { 23,    ("Telnet (sin cifrar)", 3) },
            { 135,   ("RPC", 2) },
            { 139,   ("NetBIOS", 2) },
            { 445,   ("SMB (compartir archivos)", 3) },
            { 3306,  ("MySQL", 2) },
            { 3389,  ("Escritorio remoto (RDP)", 3) },
            { 5432,  ("PostgreSQL", 2) },
            { 5900,  ("VNC", 3) },
            { 27017, ("MongoDB", 2) }
        };

        // Puertos que se prueban en los demás dispositivos de la red.
        private static readonly int[] PuertosRed = { 21, 23, 139, 445, 3389, 5900 };

        // Software que se sabe obsoleto o sin soporte.
        private static readonly (string Patron, string Motivo, int Gravedad)[] SoftwareRiesgoso =
        {
            ("Flash Player", "Adobe Flash Player está descontinuado desde 2020 y ya no recibe parches de seguridad.", 3),
            ("Silverlight", "Microsoft Silverlight llegó al fin de soporte en 2021.", 2),
            ("Python 2.", "Python 2 está sin soporte desde 2020.", 2)
        };

        public static string GetSeverityName(int level)
        {
            switch (level)
            {
                case 1:
                    return "Bajo";
                case 2:
                    return "Medio";
                case 3:
                    return "Alto";
                default:
                    return "Desconocido";
            }
        }

        // ---------------------------------------------------------------
        // Escaneo
        // ---------------------------------------------------------------
        public void Scan(ScanType tipo)
        {
            var reloj = Stopwatch.StartNew();
            var encontradas = new List<Vulnerability>();

            Notes = new List<string>();
            lastDevices = new List<NetworkDevice>();
            lastScanType = tipo;
            lastScanDate = DateTime.Now;

            if (tipo == ScanType.Equipo)
            {
                Safe(encontradas, CheckOperatingSystem);
                Safe(encontradas, CheckInstalledSoftware);
                Safe(encontradas, CheckLocalPorts);
            }
            else
            {
                Safe(encontradas, CheckNetwork);
            }

            reloj.Stop();

            Vulnerabilities = encontradas.OrderByDescending(v => v.SeverityLevel).ToList();

            scanDuration = (int)reloj.Elapsed.TotalSeconds;
            vulnerabilitiesFound = Vulnerabilities.Count;
            severityLevel = Vulnerabilities.Count > 0 ? Vulnerabilities.Max(v => v.SeverityLevel) : 0;

            totalScans++;
            totalVulnerabilities += vulnerabilitiesFound;
            totalSeverityLevel += Vulnerabilities.Sum(v => v.SeverityLevel);
            totalScanDuration += scanDuration;
        }

        // Si una revisión falla, las demás siguen.
        private void Safe(List<Vulnerability> encontradas, Action<List<Vulnerability>> revision)
        {
            try
            {
                revision(encontradas);
            }
            catch (Exception ex)
            {
                Notes.Add($"La revisión '{revision.Method.Name}' no se pudo completar: {ex.Message}");
            }
        }

        private static void Add(List<Vulnerability> encontradas, string nombre, string descripcion, int gravedad)
        {
            encontradas.Add(new Vulnerability { Name = nombre, Description = descripcion, SeverityLevel = gravedad });
        }

        // ---------------------------------------------------------------
        // Sistema operativo
        // ---------------------------------------------------------------
        private void CheckOperatingSystem(List<Vulnerability> encontradas)
        {
            if (OperatingSystem.IsWindows())
            {
                CheckWindows(encontradas);
            }
            else if (OperatingSystem.IsLinux())
            {
                CheckLinux(encontradas);
            }
            else if (OperatingSystem.IsMacOS())
            {
                CheckMac(encontradas);
            }
            else
            {
                Notes.Add("Sistema operativo no soportado para las revisiones del sistema.");
            }
        }

        [SupportedOSPlatform("windows")]
        private void CheckWindows(List<Vulnerability> encontradas)
        {
            // Firewall
            string firewall = CommandRunner.PowerShell(
                "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } | ForEach-Object { $_.Name }) -join ', '");
            if (!string.IsNullOrWhiteSpace(firewall))
            {
                Add(encontradas, "Firewall de Windows desactivado",
                    $"Perfiles sin protección: {firewall}. Actívalo para bloquear conexiones no deseadas.", 3);
            }

            // Antivirus (Microsoft Defender)
            string tiempoReal = CommandRunner.PowerShell("(Get-MpComputerStatus).RealTimeProtectionEnabled");
            if (tiempoReal.Equals("False", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "Protección en tiempo real desactivada",
                    "Microsoft Defender no está protegiendo en tiempo real. Si usas otro antivirus, puede ser normal.", 3);
            }

            string edadFirmas = CommandRunner.PowerShell("(Get-MpComputerStatus).AntivirusSignatureAge");
            if (int.TryParse(edadFirmas, out int dias) && dias > 7)
            {
                Add(encontradas, "Definiciones de antivirus desactualizadas",
                    $"Las definiciones de Defender tienen {dias} días. Actualízalas desde Seguridad de Windows.", 2);
            }

            // SMBv1 (requiere administrador)
            string smb1 = CommandRunner.PowerShell("(Get-SmbServerConfiguration).EnableSMB1Protocol");
            if (smb1.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "SMBv1 habilitado",
                    "SMBv1 es un protocolo antiguo y vulnerable (usado por ataques como WannaCry). Desactívalo.", 3);
            }

            // Escritorio remoto
            object? rdp = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", null);
            if (rdp is int valorRdp && valorRdp == 0)
            {
                Add(encontradas, "Escritorio remoto habilitado",
                    "Este equipo acepta conexiones por Escritorio remoto. Si no lo usas, desactívalo.", 2);
            }

            // Control de cuentas de usuario (UAC)
            object? uac = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", null);
            if (uac is int valorUac && valorUac == 0)
            {
                Add(encontradas, "Control de cuentas de usuario (UAC) desactivado",
                    "Sin UAC, cualquier programa puede ejecutarse con permisos elevados sin avisarte.", 3);
            }

            // Cuenta de invitado
            string invitado = CommandRunner.PowerShell("(Get-LocalUser -Name 'Guest').Enabled");
            if (invitado.Equals("True", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "Cuenta de invitado habilitada",
                    "La cuenta Guest está activa. Desactívala si no la necesitas.", 2);
            }

            // Parches recientes
            string fecha = CommandRunner.PowerShell(
                "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')");
            if (DateTime.TryParseExact(fecha, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime ultimoParche)
                && (DateTime.Now - ultimoParche).TotalDays > 60)
            {
                Add(encontradas, "Sin parches de seguridad recientes",
                    $"La última actualización instalada es del {ultimoParche:dd/MM/yyyy}. Revisa Windows Update.", 2);
            }
        }

        private void CheckLinux(List<Vulnerability> encontradas)
        {
            const string sshConfig = "/etc/ssh/sshd_config";

            if (File.Exists(sshConfig))
            {
                foreach (string linea in File.ReadAllLines(sshConfig))
                {
                    if (Regex.IsMatch(linea, @"^\s*PermitRootLogin\s+yes\b", RegexOptions.IgnoreCase))
                    {
                        Add(encontradas, "Login de root por SSH habilitado",
                            "PermitRootLogin está en 'yes' en sshd_config. Usa un usuario normal con sudo.", 3);
                    }
                }
            }

            string ufw = CommandRunner.Run("ufw", new[] { "status" });
            if (ufw.Contains("inactive", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "Firewall (ufw) inactivo",
                    "ufw está instalado pero desactivado. Actívalo con 'sudo ufw enable'.", 2);
            }

            string apt = CommandRunner.Run("apt", new[] { "list", "--upgradable" });
            int pendientes = apt.Split('\n').Count(l => l.Contains("upgradable", StringComparison.OrdinalIgnoreCase));
            if (pendientes > 0)
            {
                Add(encontradas, "Actualizaciones pendientes",
                    $"Hay {pendientes} paquetes con actualización disponible. Ejecuta 'sudo apt update && sudo apt upgrade'.", 2);
            }
        }

        private void CheckMac(List<Vulnerability> encontradas)
        {
            string firewall = CommandRunner.Run("/usr/libexec/ApplicationFirewall/socketfilterfw", new[] { "--getglobalstate" });
            if (firewall.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "Firewall de macOS desactivado",
                    "Actívalo en Ajustes del Sistema > Red > Firewall.", 3);
            }

            string sip = CommandRunner.Run("csrutil", new[] { "status" });
            if (sip.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "SIP (System Integrity Protection) desactivado",
                    "SIP protege los archivos del sistema. Se reactiva desde el modo de recuperación.", 3);
            }

            string fileVault = CommandRunner.Run("fdesetup", new[] { "status" });
            if (fileVault.Contains("FileVault is Off", StringComparison.OrdinalIgnoreCase))
            {
                Add(encontradas, "FileVault desactivado",
                    "El disco no está cifrado. Actívalo en Ajustes del Sistema > Privacidad y seguridad.", 2);
            }
        }

        // ---------------------------------------------------------------
        // Programas instalados
        // ---------------------------------------------------------------
        private void CheckInstalledSoftware(List<Vulnerability> encontradas)
        {
            if (!OperatingSystem.IsWindows())
            {
                Notes.Add("La revisión de programas instalados solo está disponible en Windows por ahora.");
                return;
            }

            List<(string Nombre, string Version)> programas = GetInstalledPrograms();
            installedProgramsCount = programas.Count;

            foreach ((string nombre, string version) in programas)
            {
                foreach (var regla in SoftwareRiesgoso)
                {
                    if (nombre.Contains(regla.Patron, StringComparison.OrdinalIgnoreCase))
                    {
                        Add(encontradas, $"Software obsoleto: {nombre}", regla.Motivo, regla.Gravedad);
                    }
                }

                if (nombre.StartsWith("WinRAR", StringComparison.OrdinalIgnoreCase)
                    && System.Version.TryParse(version, out Version? v)
                    && v < new Version(6, 23))
                {
                    Add(encontradas, $"WinRAR desactualizado ({version})",
                        "Las versiones anteriores a 6.23 tienen una vulnerabilidad de ejecución de código (CVE-2023-38831). Actualiza WinRAR.", 3);
                }
            }

            Notes.Add("La revisión de programas usa una lista corta de software conocido como riesgoso; no consulta la base de datos de CVE.");
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

        // ---------------------------------------------------------------
        // Puertos abiertos en este equipo
        // ---------------------------------------------------------------
        private void CheckLocalPorts(List<Vulnerability> encontradas)
        {
            IPEndPoint[] escuchando = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            var reportados = new HashSet<int>();

            foreach (IPEndPoint punto in escuchando)
            {
                // Solo cuentan los puertos accesibles desde la red (no los que escuchan solo en localhost).
                if (!IPAddress.IsLoopback(punto.Address)
                    && reportados.Add(punto.Port)
                    && PuertosRiesgosos.TryGetValue(punto.Port, out var info))
                {
                    Add(encontradas, $"Puerto {punto.Port} abierto",
                        $"{info.Servicio} está aceptando conexiones desde la red. Si no lo usas, ciérralo o bloquéalo en el firewall.",
                        info.Gravedad);
                }
            }
        }

        // ---------------------------------------------------------------
        // Red
        // ---------------------------------------------------------------
        private void CheckNetwork(List<Vulnerability> encontradas)
        {
            (IPAddress? miIp, IPAddress? puertaEnlace) = GetNetworkInfo();

            if (miIp == null)
            {
                Notes.Add("No se encontró una conexión de red activa.");
                return;
            }

            gateway = puertaEnlace;

            string[] octetos = miIp.ToString().Split('.');
            string prefijo = $"{octetos[0]}.{octetos[1]}.{octetos[2]}.";

            List<string> hosts = DiscoverHosts(prefijo, miIp.ToString()).GetAwaiter().GetResult();
            Dictionary<string, string> tablaArp = GetArpTable();

            lastDevices = hosts
                .Select(ip => new NetworkDevice { Ip = ip, Mac = tablaArp.TryGetValue(ip, out string? mac) ? mac : "" })
                .ToList();

            Notes.Add($"Se escaneó la subred {prefijo}0/24 y se encontraron {lastDevices.Count} dispositivos que responden a ping. Los que bloquean ping pueden no aparecer.");

            // Puertos riesgosos en cada dispositivo
            var pruebas = new List<Task<(string Ip, int Puerto, bool Abierto)>>();
            foreach (string ip in hosts)
            {
                foreach (int puerto in PuertosRed)
                {
                    pruebas.Add(ProbarPuerto(ip, puerto));
                }
            }

            var resultados = Task.WhenAll(pruebas).GetAwaiter().GetResult();

            foreach (var r in resultados)
            {
                if (r.Abierto && PuertosRiesgosos.TryGetValue(r.Puerto, out var info))
                {
                    bool esRouter = puertaEnlace != null && r.Ip == puertaEnlace.ToString();
                    string etiqueta = esRouter ? " (router)" : "";

                    Add(encontradas, $"Puerto {r.Puerto} abierto en {r.Ip}{etiqueta}",
                        $"{info.Servicio} accesible desde la red local. Revisa si ese dispositivo necesita tenerlo abierto.",
                        info.Gravedad);
                }
            }

            // Dispositivos desconocidos
            if (lastDevices.Count > 0)
            {
                if (!File.Exists(TrustedFile))
                {
                    SaveTrusted(lastDevices);
                    Notes.Add($"Primer escaneo de red: los {lastDevices.Count} dispositivos encontrados se guardaron como confiables en '{TrustedFile}'. Verifica que todos sean tuyos.");
                }
                else
                {
                    var confiables = new HashSet<string>(File.ReadAllLines(TrustedFile).Select(l => l.Trim()));

                    foreach (NetworkDevice d in lastDevices)
                    {
                        if (!confiables.Contains(d.Id))
                        {
                            string mac = string.IsNullOrEmpty(d.Mac) ? "no disponible" : d.Mac;
                            Add(encontradas, $"Dispositivo nuevo en la red: {d.Ip}",
                                $"No estaba en tu lista de dispositivos confiables (MAC: {mac}). Si no lo reconoces, cambia la contraseña del WiFi.",
                                2);
                        }
                    }
                }
            }
        }

        private static (IPAddress? Ip, IPAddress? Gateway) GetNetworkInfo()
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

        private static async Task<(string Ip, int Puerto, bool Abierto)> ProbarPuerto(string ip, int puerto)
        {
            bool abierto = await PuertoAbierto(ip, puerto);
            return (ip, puerto, abierto);
        }

        private static async Task<bool> PuertoAbierto(string ip, int puerto, int timeoutMs = 700)
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

        private static void SaveTrusted(IEnumerable<NetworkDevice> dispositivos)
        {
            var ids = new HashSet<string>();

            if (File.Exists(TrustedFile))
            {
                foreach (string linea in File.ReadAllLines(TrustedFile))
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

            File.WriteAllLines(TrustedFile, ids);
        }

        // ---------------------------------------------------------------
        // Reporte
        // ---------------------------------------------------------------
        public void GenerateReport()
        {
            var reporte = new Report
            {
                ScanDate = lastScanDate,
                Vulnerabilities = Vulnerabilities,
                TotalVulnerabilities = vulnerabilitiesFound,
                TotalSeverityLevel = Vulnerabilities.Sum(v => v.SeverityLevel)
            };

            var sb = new StringBuilder();
            sb.AppendLine("REPORTE DE VULNERABILIDADES - snaktools");
            sb.AppendLine("=======================================");
            sb.AppendLine($"Fecha y hora del escaneo: {reporte.ScanDate:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"Tipo de escaneo: {(lastScanType == ScanType.Equipo ? "Equipo" : "Red")}");
            sb.AppendLine($"Duración: {scanDuration} s");
            sb.AppendLine($"Sistema: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
            sb.AppendLine($"Vulnerabilidades encontradas: {reporte.TotalVulnerabilities}");
            sb.AppendLine($"Gravedad más alta: {(severityLevel == 0 ? "Ninguna" : GetSeverityName(severityLevel))}");
            sb.AppendLine($"Puntaje de riesgo (suma de gravedades): {reporte.TotalSeverityLevel}");
            sb.AppendLine($"Escaneos en esta sesión: {totalScans} ({totalVulnerabilities} vulnerabilidades en total, {totalScanDuration} s, gravedad acumulada {totalSeverityLevel})");

            if (lastScanType == ScanType.Equipo && installedProgramsCount > 0)
            {
                sb.AppendLine($"Programas instalados revisados: {installedProgramsCount}");
            }

            sb.AppendLine();

            if (reporte.Vulnerabilities.Count == 0)
            {
                sb.AppendLine("No se encontraron vulnerabilidades con las revisiones actuales.");
            }
            else
            {
                foreach (var grupo in reporte.Vulnerabilities.GroupBy(v => v.SeverityLevel).OrderByDescending(g => g.Key))
                {
                    sb.AppendLine($"=== Gravedad {GetSeverityName(grupo.Key)} ({grupo.Count()}) ===");

                    foreach (Vulnerability v in grupo)
                    {
                        sb.AppendLine($"- {v.Name}");
                        sb.AppendLine($"  {v.Description}");
                    }

                    sb.AppendLine();
                }
            }

            if (lastScanType == ScanType.Red && lastDevices.Count > 0)
            {
                sb.AppendLine("=== Dispositivos activos en la red ===");
                foreach (NetworkDevice d in lastDevices)
                {
                    string etiqueta = gateway != null && d.Ip == gateway.ToString() ? " (router)" : "";
                    sb.AppendLine($"- {d.Ip}{etiqueta}  MAC: {(string.IsNullOrEmpty(d.Mac) ? "no disponible" : d.Mac)}");
                }
                sb.AppendLine();
            }

            if (Notes.Count > 0)
            {
                sb.AppendLine("=== Notas ===");
                foreach (string nota in Notes)
                {
                    sb.AppendLine($"- {nota}");
                }
            }

            File.WriteAllText(ReportFile, sb.ToString(), Encoding.UTF8);
            ReportPath = Path.GetFullPath(ReportFile);
        }

        // ---------------------------------------------------------------
        // Notificación
        // ---------------------------------------------------------------
        public void NotifyUser()
        {
            var notificacion = new Notification();
            notificacion.Show($"Escaneo completado. Vulnerabilidades encontradas: {vulnerabilitiesFound}. El reporte fue guardado.");
        }

        // ---------------------------------------------------------------
        // Medidas
        // ---------------------------------------------------------------
        public void TakeActionOnVulnerabilities()
        {
            bool volver = false;

            while (!volver)
            {
                Console.WriteLine();
                Console.WriteLine("Medidas disponibles:");
                Console.WriteLine("1. Actualizar el sistema operativo");
                Console.WriteLine("2. Revisar el firewall");
                Console.WriteLine("3. Revisar o desinstalar programas instalados");
                Console.WriteLine("4. Abrir el panel del router (para cambiar la contraseña de la red)");
                Console.WriteLine("5. Marcar los dispositivos actuales de la red como confiables");
                Console.WriteLine("6. Volver al menú");
                Console.Write("Opción: ");

                switch ((Console.ReadLine() ?? "").Trim())
                {
                    case "1":
                        ActualizarSistema();
                        break;
                    case "2":
                        RevisarFirewall();
                        break;
                    case "3":
                        RevisarProgramas();
                        break;
                    case "4":
                        AbrirRouter();
                        break;
                    case "5":
                        MarcarDispositivosConfiables();
                        break;
                    case "6":
                        volver = true;
                        break;
                    default:
                        Console.WriteLine("Opción inválida.");
                        break;
                }
            }
        }

        private static void ActualizarSistema()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("ms-settings:windowsupdate");
            }
            else if (OperatingSystem.IsLinux())
            {
                Console.WriteLine("Ejecuta en una terminal: sudo apt update && sudo apt upgrade (o el gestor de tu distribución).");
            }
            else
            {
                Console.WriteLine("Ve a Ajustes del Sistema > General > Actualización de software.");
            }
        }

        private static void RevisarFirewall()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("firewall.cpl");
            }
            else if (OperatingSystem.IsLinux())
            {
                Console.WriteLine("Ejecuta en una terminal: sudo ufw enable");
            }
            else
            {
                Console.WriteLine("Ve a Ajustes del Sistema > Red > Firewall.");
            }
        }

        private static void RevisarProgramas()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("appwiz.cpl");
            }
            else
            {
                Console.WriteLine("Usa el gestor de paquetes de tu sistema para actualizar o quitar el software riesgoso.");
            }
        }

        private void AbrirRouter()
        {
            IPAddress? puerta = gateway ?? GetNetworkInfo().Gateway;

            if (puerta == null)
            {
                Console.WriteLine("No se encontró el router. Revisa tu conexión de red.");
            }
            else
            {
                Console.WriteLine($"Abriendo http://{puerta} ... Inicia sesión y cambia la contraseña del WiFi y la del panel de administración.");
                OpenTarget($"http://{puerta}");
            }
        }

        private void MarcarDispositivosConfiables()
        {
            if (lastDevices.Count == 0)
            {
                Console.WriteLine("Primero haz un escaneo de red (opción 2 del menú) para tener la lista de dispositivos.");
            }
            else
            {
                SaveTrusted(lastDevices);
                Console.WriteLine($"Se marcaron {lastDevices.Count} dispositivos como confiables en '{TrustedFile}'.");
            }
        }

        private static void OpenTarget(string destino)
        {
            try
            {
                Process.Start(new ProcessStartInfo(destino) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"No se pudo abrir '{destino}': {ex.Message}");
            }
        }
    }
}
