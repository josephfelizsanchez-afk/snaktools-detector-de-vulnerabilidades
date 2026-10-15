using System.Net.NetworkInformation;
using System.Xml.Linq;

namespace snaktools
{
    // Un perfil de red WiFi guardado en el equipo (sin contraseñas).
    class WifiProfile
    {
        public string Name { get; set; } = "";
        public string Ssid { get; set; } = "";
        public string Authentication { get; set; } = "";   // open, shared, WPAPSK, WPA2PSK, WPA3SAE...
        public string Encryption { get; set; } = "";       // none, WEP, TKIP, AES
        public string ConnectionMode { get; set; } = "";   // auto o manual
    }

    internal static class WifiChecks
    {
        public static void Run(ScanContext ctx)
        {
            if (OperatingSystem.IsWindows())
            {
                CheckWindows(ctx);
            }
            else if (OperatingSystem.IsLinux())
            {
                CheckLinux(ctx);
            }
            else
            {
                ctx.Notes.Add("La revisión del WiFi no está disponible en este sistema operativo.");
            }
        }

        // ---------------------------------------------------------------
        // Windows
        // El adaptador activo se detecta con .NET y la seguridad se lee de los perfiles guardados,
        // así no depende de los servicios de ubicación (que bloquean "netsh wlan show interfaces").
        // ---------------------------------------------------------------
        private static void CheckWindows(ScanContext ctx)
        {
            List<NetworkInterface> adaptadores = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                .ToList();

            if (adaptadores.Count == 0)
            {
                ctx.Notes.Add("WiFi: este equipo no tiene adaptador WiFi, se omitió esta revisión.");
                return;
            }

            NetworkInterface? activo = adaptadores.FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up);
            List<WifiProfile> perfiles = ReadProfilesWindows();

            if (activo == null)
            {
                ctx.Notes.Add("WiFi: el equipo no está conectado a ninguna red WiFi en este momento.");
            }
            else
            {
                EvaluateActiveWindows(ctx, activo, perfiles);
            }

            ReportOpenProfiles(ctx, perfiles);
        }

        private static void EvaluateActiveWindows(ScanContext ctx, NetworkInterface activo, List<WifiProfile> perfiles)
        {
            // Nombre del perfil de la red conectada
            string nombre = CommandRunner.PowerShell(
                "(Get-NetConnectionProfile -InterfaceAlias '" + activo.Name.Replace("'", "''") + "' | Select-Object -First 1).Name");

            if (nombre == "")
            {
                nombre = ProfileNameFromNetsh();
            }

            WifiProfile? actual = null;

            if (nombre != "")
            {
                actual = perfiles.FirstOrDefault(p => p.Name.Equals(nombre, StringComparison.OrdinalIgnoreCase))
                      ?? perfiles.FirstOrDefault(p => p.Ssid.Equals(nombre, StringComparison.OrdinalIgnoreCase));
            }

            if (actual != null)
            {
                RateAndReport(ctx, actual.Authentication, actual.Encryption);
                return;
            }

            // Plan B: leer la seguridad en texto con "netsh wlan show interfaces"
            if (!EvaluateFromNetshText(ctx))
            {
                ctx.Notes.Add("WiFi: estás conectado por WiFi, pero no se pudo leer el tipo de seguridad. " +
                              "En Windows 11 reciente puede requerir activar Configuración > Privacidad y seguridad > Ubicación.");
            }
        }

        private static List<WifiProfile> ReadProfilesWindows()
        {
            var lista = new List<WifiProfile>();
            string carpeta = Path.Combine(Path.GetTempPath(), "snaktools_wifi_" + Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(carpeta);

                // Exporta los perfiles guardados a XML (sin las contraseñas) en una carpeta temporal.
                CommandRunner.Run("netsh", new[] { "wlan", "export", "profile", "folder=" + carpeta });

                foreach (string archivo in Directory.GetFiles(carpeta, "*.xml"))
                {
                    WifiProfile? perfil = ParseProfile(File.ReadAllText(archivo));

                    if (perfil != null)
                    {
                        lista.Add(perfil);
                    }
                }
            }
            catch (Exception)
            {
                // Si falla, se usa el plan B.
            }
            finally
            {
                try
                {
                    if (Directory.Exists(carpeta))
                    {
                        Directory.Delete(carpeta, true);
                    }
                }
                catch (Exception)
                {
                }
            }

            return lista;
        }

        public static WifiProfile? ParseProfile(string xml)
        {
            try
            {
                XElement? raiz = XDocument.Parse(xml).Root;

                if (raiz == null)
                {
                    return null;
                }

                string Texto(IEnumerable<XElement> elementos, string nombre)
                {
                    return elementos.FirstOrDefault(e => e.Name.LocalName == nombre)?.Value.Trim() ?? "";
                }

                XElement? ssid = raiz.Descendants().FirstOrDefault(e => e.Name.LocalName == "SSID");

                return new WifiProfile
                {
                    Name = Texto(raiz.Elements(), "name"),
                    Ssid = ssid == null ? "" : Texto(ssid.Elements(), "name"),
                    ConnectionMode = Texto(raiz.Elements(), "connectionMode"),
                    Authentication = Texto(raiz.Descendants(), "authentication"),
                    Encryption = Texto(raiz.Descendants(), "encryption")
                };
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Plan B para el nombre del perfil
        private static string ProfileNameFromNetsh()
        {
            string salida = CommandRunner.Run("netsh", new[] { "wlan", "show", "interfaces" });

            foreach (string linea in salida.Split('\n'))
            {
                int pos = linea.IndexOf(':');

                if (pos > 0)
                {
                    string clave = linea.Substring(0, pos).Trim().ToLower();

                    if (clave == "profile" || clave == "perfil")
                    {
                        return linea.Substring(pos + 1).Trim();
                    }
                }
            }

            return "";
        }

        // Plan B para la seguridad: devuelve false si no se pudo leer.
        private static bool EvaluateFromNetshText(ScanContext ctx)
        {
            string salida = CommandRunner.Run("netsh", new[] { "wlan", "show", "interfaces" });
            string autenticacion = "";
            string cifrado = "";

            // Los nombres de los campos cambian según el idioma de Windows,
            // por eso se buscan fragmentos comunes (inglés, español, francés, alemán, portugués).
            foreach (string linea in salida.Split('\n'))
            {
                int pos = linea.IndexOf(':');

                if (pos > 0)
                {
                    string nombre = linea.Substring(0, pos).Trim().ToLower();
                    string valor = linea.Substring(pos + 1).Trim();

                    if (nombre.Contains("authentic") || nombre.Contains("autentic") || nombre.Contains("authentif"))
                    {
                        autenticacion = valor;
                    }
                    else if (nombre.Contains("cipher") || nombre.Contains("cifrado") || nombre.Contains("chiffrement"))
                    {
                        cifrado = valor;
                    }
                }
            }

            if (autenticacion == "")
            {
                return false;
            }

            string a = autenticacion.ToLower();
            string c = cifrado.ToLower();
            string codigo;

            if (a.Contains("wpa3")) codigo = "wpa3sae";
            else if (a.Contains("wpa2")) codigo = "wpa2psk";
            else if (a.Contains("wpa")) codigo = "wpapsk";
            else if (a.Contains("wep") || c.Contains("wep")) codigo = "open";
            else if (a.Contains("open") || a.Contains("abiert") || a.Contains("abrir")) codigo = "open";
            else if (a.Contains("shared") || a.Contains("compartid")) codigo = "shared";
            else return false;

            string cifrar = c.Contains("tkip") ? "tkip" : c.Contains("wep") ? "wep" : c.Contains("none") || c.Contains("ning") ? "none" : "aes";
            RateAndReport(ctx, codigo, cifrar);
            return true;
        }

        // Avisa si el equipo guarda redes abiertas y se conecta a ellas solo.
        private static void ReportOpenProfiles(ScanContext ctx, List<WifiProfile> perfiles)
        {
            List<WifiProfile> abiertas = perfiles
                .Where(p => p.Authentication.Equals("open", StringComparison.OrdinalIgnoreCase)
                         && p.ConnectionMode.Equals("auto", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (abiertas.Count > 0)
            {
                string nombres = string.Join(", ", abiertas.Take(5).Select(p => p.Name));

                ctx.Add("Redes WiFi abiertas guardadas con conexión automática",
                    $"El equipo guarda {abiertas.Count} red(es) WiFi sin contraseña y se conecta sola: {nombres}. " +
                    "Un atacante podría imitar una de ellas. Olvídalas en Configuración > Red e Internet > WiFi > Administrar redes conocidas.",
                    Severity.Medio);
            }
        }

        // ---------------------------------------------------------------
        // Linux
        // ---------------------------------------------------------------
        private static void CheckLinux(ScanContext ctx)
        {
            string salida = CommandRunner.Run("nmcli", new[] { "-t", "-f", "ACTIVE,SECURITY", "dev", "wifi" });
            string seguridad = "";
            bool conectado = false;

            foreach (string linea in salida.Split('\n'))
            {
                if (linea.StartsWith("yes:", StringComparison.OrdinalIgnoreCase))
                {
                    conectado = true;
                    seguridad = linea.Substring(4).Trim();
                }
            }

            if (!conectado)
            {
                ctx.Notes.Add("WiFi: no hay una conexión WiFi activa (o nmcli no está disponible), se omitió esta revisión.");
                return;
            }

            string autenticacion;
            string cifrado = "aes";

            if (seguridad == "" || seguridad == "--")
            {
                autenticacion = "open";
                cifrado = "none";
            }
            else if (seguridad.Contains("WPA3")) autenticacion = "wpa3sae";
            else if (seguridad.Contains("WPA2")) autenticacion = "wpa2psk";
            else if (seguridad.Contains("WPA")) { autenticacion = "wpapsk"; cifrado = "tkip"; }
            else if (seguridad.Contains("WEP")) { autenticacion = "open"; cifrado = "wep"; }
            else
            {
                ctx.Notes.Add("WiFi: no se reconoció el tipo de seguridad (" + seguridad + ").");
                return;
            }

            RateAndReport(ctx, autenticacion, cifrado);
        }

        // ---------------------------------------------------------------
        // Evaluación común
        // ---------------------------------------------------------------
        private static void RateAndReport(ScanContext ctx, string autenticacion, string cifrado)
        {
            ctx.Notes.Add("WiFi conectado: seguridad " + FriendlyName(autenticacion) + (cifrado == "" ? "" : " (cifrado " + cifrado + ")") + ".");

            (int Nivel, string Nombre, string Descripcion)? resultado = Rate(autenticacion, cifrado);

            if (resultado != null)
            {
                ctx.Add(resultado.Value.Nombre, resultado.Value.Descripcion, resultado.Value.Nivel);
            }
        }

        // Devuelve null si la seguridad es buena.
        public static (int Nivel, string Nombre, string Descripcion)? Rate(string autenticacion, string cifrado)
        {
            string a = autenticacion.ToLower();
            string c = cifrado.ToLower();

            if (a == "open")
            {
                if (c == "wep")
                {
                    return (Severity.Alto, "WiFi con cifrado WEP",
                        "La red usa WEP, un cifrado que se rompe en minutos. En el router cambia a WPA2 o WPA3.");
                }

                return (Severity.Alto, "WiFi abierto (sin contraseña)",
                    "La red WiFi no tiene contraseña: cualquiera cerca puede ver tu tráfico no cifrado. Evita usarla o usa una VPN.");
            }

            if (a == "shared")
            {
                return (Severity.Alto, "WiFi con cifrado WEP",
                    "La red usa WEP, un cifrado que se rompe en minutos. En el router cambia a WPA2 o WPA3.");
            }

            if (a == "wpa" || a == "wpapsk")
            {
                return (Severity.Medio, "WiFi con WPA (antiguo)",
                    "La red usa WPA, que es vulnerable. En el router cambia a WPA2 o WPA3.");
            }

            if ((a == "wpa2" || a == "wpa2psk") && c == "tkip")
            {
                return (Severity.Medio, "WiFi con cifrado TKIP",
                    "La red usa WPA2 con TKIP, un cifrado antiguo. En el router elige WPA2 con AES (CCMP) o WPA3.");
            }

            return null;
        }

        private static string FriendlyName(string autenticacion)
        {
            switch (autenticacion.ToLower())
            {
                case "open": return "abierta";
                case "shared": return "WEP compartida";
                case "wpa": return "WPA-Enterprise";
                case "wpapsk": return "WPA-Personal";
                case "wpa2": return "WPA2-Enterprise";
                case "wpa2psk": return "WPA2-Personal";
                case "wpa3sae": return "WPA3-Personal";
                case "wpa3": return "WPA3-Enterprise";
                case "wpa3ent": return "WPA3-Enterprise";
                case "wpa3ent192": return "WPA3-Enterprise 192 bits";
                case "owe": return "Enhanced Open (OWE)";
                default: return autenticacion;
            }
        }
    }
}
