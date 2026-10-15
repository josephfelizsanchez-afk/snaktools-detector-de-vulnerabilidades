using System.Net;
using System.Text.RegularExpressions;

namespace snaktools
{
    // Algo que se puede hacer de inmediato para frenar una intrusión. Todo es reversible.
    class ContainmentAction
    {
        public string Kind { get; set; } = "";          // BloquearIp, TerminarProceso, DesactivarRdp, QuitarExclusion, DesactivarInvitado
        public string Target { get; set; } = "";
        public string Description { get; set; } = "";
        public bool Recommended { get; set; }           // se sugiere aplicarla
        public bool AutoSafe { get; set; }              // es seguro aplicarla sola si la contención automática está activada
    }

    class IntrusionFinding
    {
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public int Severity { get; set; }
        public string Confidence { get; set; } = "Media";    // Alta, Media, Baja
        public string Tag { get; set; } = "";
        public List<string> Evidence { get; set; } = new List<string>();
        public List<ContainmentAction> Actions { get; set; } = new List<ContainmentAction>();
    }

    class ConnectionInfo
    {
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public int Pid { get; set; }
    }

    class LogonEvent
    {
        public DateTime Time { get; set; }
        public string User { get; set; } = "";
        public string Ip { get; set; } = "";
        public string Type { get; set; } = "";
    }

    class IntrusionInputs
    {
        public PathContext Paths { get; set; } = new PathContext();
        public List<ConnectionInfo> Connections { get; set; } = new List<ConnectionInfo>();
        public List<ProcInfo> Processes { get; set; } = new List<ProcInfo>();
        public List<LogonEvent> Logons { get; set; } = new List<LogonEvent>();
        public List<LogonEvent> FailedLogons { get; set; } = new List<LogonEvent>();
        public List<LogonEvent> NewUsers { get; set; } = new List<LogonEvent>();
        public List<LogonEvent> AdminAdds { get; set; } = new List<LogonEvent>();
        public List<DateTime> LogsCleared { get; set; } = new List<DateTime>();
        public List<string> ExclusionPaths { get; set; } = new List<string>();
        public List<string> ExclusionProcesses { get; set; } = new List<string>();
        public List<string> ExclusionExtensions { get; set; } = new List<string>();
        public List<string> HostsLines { get; set; } = new List<string>();
        public string ProxyServer { get; set; } = "";
        public string AutoConfigUrl { get; set; } = "";
        public List<string> RemoteServices { get; set; } = new List<string>();
        public bool EventLogReadable { get; set; } = true;
    }

    internal static class IntrusionChecks
    {
        private static readonly int[] PuertosExpuestos = { 3389, 5900, 5901, 22, 23, 5985, 5986, 445 };
        private static readonly int[] PuertosDeControl = { 4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321 };
        private static readonly int[] PuertosPuertaTrasera = { 4444, 31337, 1337, 12345, 54321 };

        private static readonly (Regex Patron, string Nombre)[] HerramientasRemotas =
        {
            (new Regex(@"anydesk", RegexOptions.IgnoreCase), "AnyDesk"),
            (new Regex(@"teamviewer|tv_w32|tv_x64", RegexOptions.IgnoreCase), "TeamViewer"),
            (new Regex(@"winvnc|tvnserver|tightvnc|ultravnc|uvnc", RegexOptions.IgnoreCase), "VNC"),
            (new Regex(@"rustdesk", RegexOptions.IgnoreCase), "RustDesk"),
            (new Regex(@"ammyy|aa_v3", RegexOptions.IgnoreCase), "Ammyy Admin"),
            (new Regex(@"logmein|lmi_rescue", RegexOptions.IgnoreCase), "LogMeIn"),
            (new Regex(@"screenconnect|connectwise", RegexOptions.IgnoreCase), "ScreenConnect/ConnectWise"),
            (new Regex(@"splashtop|srservice", RegexOptions.IgnoreCase), "Splashtop"),
            (new Regex(@"radmin|rserver3", RegexOptions.IgnoreCase), "Radmin"),
            (new Regex(@"supremo", RegexOptions.IgnoreCase), "Supremo"),
            (new Regex(@"remoting_host", RegexOptions.IgnoreCase), "Escritorio remoto de Chrome"),
            (new Regex(@"meshagent", RegexOptions.IgnoreCase), "MeshCentral"),
            (new Regex(@"client32|netsupport", RegexOptions.IgnoreCase), "NetSupport"),
            (new Regex(@"dwagent|remotepc|zohoassist|gotomypc", RegexOptions.IgnoreCase), "Acceso remoto")
        };

        // ---------------------------------------------------------------
        // Direcciones IP
        // ---------------------------------------------------------------
        public static bool IsPublicIp(string texto)
        {
            if (!IPAddress.TryParse((texto ?? "").Trim(), out IPAddress? ip))
            {
                return false;
            }

            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }

            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None))
            {
                return false;
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                byte[] b6 = ip.GetAddressBytes();
                bool linkLocal = b6[0] == 0xFE && (b6[1] & 0xC0) == 0x80;
                bool unicaLocal = (b6[0] & 0xFE) == 0xFC;
                bool multicast = b6[0] == 0xFF;
                return !(linkLocal || unicaLocal || multicast);
            }

            byte[] b = ip.GetAddressBytes();

            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;   // CGNAT
            if (b[0] >= 224) return false;                                  // multicast y reservadas
            return true;
        }

        // ---------------------------------------------------------------
        // Archivo hosts
        // ---------------------------------------------------------------
        public static (int Severidad, string Descripcion)? AnalyzeHosts(IEnumerable<string> lineas)
        {
            var raras = new List<string>();
            var seguridad = new List<string>();

            foreach (string linea in lineas)
            {
                string limpia = linea.Split('#')[0].Trim();

                if (limpia == "")
                {
                    continue;
                }

                string[] partes = limpia.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                if (partes.Length < 2)
                {
                    continue;
                }

                string ip = partes[0];
                string[] dominios = partes.Skip(1).ToArray();
                bool soloLocalhost = dominios.All(d => d.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                                                    || d.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase)
                                                    || d.Equals("broadcasthost", StringComparison.OrdinalIgnoreCase));

                if (soloLocalhost)
                {
                    continue;
                }

                string todos = string.Join(" ", dominios);

                if (Regex.IsMatch(todos, @"virustotal|kaspersky|malwarebytes|windowsupdate|update\.microsoft|defender|avast|\bavg\b|eset|norton|mcafee|bitdefender|sophos|trendmicro", RegexOptions.IgnoreCase))
                {
                    seguridad.Add(limpia);
                }
                else
                {
                    raras.Add(limpia);
                }
            }

            if (seguridad.Count > 0)
            {
                return (Severity.Alto, "El archivo hosts bloquea o redirige sitios de seguridad o de actualización de Windows (" + string.Join("; ", seguridad.Take(3)) + "). Los virus lo hacen para que el antivirus no se actualice.");
            }

            if (raras.Count > 0)
            {
                return (Severity.Medio, $"El archivo hosts tiene {raras.Count} entrada(s) personalizada(s) (por ejemplo: {raras[0]}). Si no las agregaste tú, pueden redirigirte a páginas falsas.");
            }

            return null;
        }

        // ---------------------------------------------------------------
        // Análisis principal
        // ---------------------------------------------------------------
        public static List<IntrusionFinding> Analyze(IntrusionInputs d, IntrusionConfig cfg)
        {
            var hallazgos = new List<IntrusionFinding>();
            var procesosPorPid = d.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
            var yaReportado = new HashSet<string>();

            ProcInfo? Proceso(int pid) => procesosPorPid.TryGetValue(pid, out ProcInfo? p) ? p : null;
            bool EsDeConfianza(ProcInfo? p) => p != null && p.Path != "" && (d.Paths.IsWindowsDir(p.Path) || d.Paths.IsProgramFiles(p.Path));

            // 1) Alguien de internet conectado ahora mismo a este equipo
            foreach (ConnectionInfo c in d.Connections.Where(c => c.State.Equals("Established", StringComparison.OrdinalIgnoreCase)
                                                              && PuertosExpuestos.Contains(c.LocalPort)
                                                              && IsPublicIp(c.RemoteAddress)))
            {
                if (!yaReportado.Add("sesion|" + c.RemoteAddress))
                {
                    continue;
                }

                var h = new IntrusionFinding
                {
                    Title = $"Conexión remota activa desde internet ({c.RemoteAddress})",
                    Description = $"Ahora mismo hay alguien desde internet ({c.RemoteAddress}) conectado a este equipo por el puerto {c.LocalPort} ({NombrePuerto(c.LocalPort)}). Si no eres tú ni alguien de confianza, es un acceso no autorizado.",
                    Severity = Severity.Alto,
                    Confidence = "Alta",
                    Tag = "sesion-remota-activa"
                };
                h.Evidence.Add($"{c.RemoteAddress}:{c.RemotePort} -> puerto local {c.LocalPort}");
                h.Actions.Add(new ContainmentAction { Kind = "BloquearIp", Target = c.RemoteAddress, Description = $"Bloquear la IP {c.RemoteAddress} en el firewall (entrada y salida)", Recommended = true, AutoSafe = true });

                if (c.LocalPort == 3389)
                {
                    h.Actions.Add(new ContainmentAction { Kind = "DesactivarRdp", Target = "RDP", Description = "Desactivar el Escritorio remoto de Windows", Recommended = true });
                }

                hallazgos.Add(h);
            }

            // 2) Programas que se comunican con puertos típicos de control remoto de malware
            foreach (ConnectionInfo c in d.Connections.Where(c => c.State.Equals("Established", StringComparison.OrdinalIgnoreCase)
                                                              && PuertosDeControl.Contains(c.RemotePort)
                                                              && IsPublicIp(c.RemoteAddress)))
            {
                ProcInfo? p = Proceso(c.Pid);

                if (EsDeConfianza(p) || !yaReportado.Add("c2|" + c.RemoteAddress + "|" + c.Pid))
                {
                    continue;
                }

                string quien = p == null ? $"un proceso (PID {c.Pid})" : $"{p.Name} ({p.Path})";
                var h = new IntrusionFinding
                {
                    Title = $"Programa conectado a un puerto típico de control remoto ({c.RemoteAddress}:{c.RemotePort})",
                    Description = $"{quien} está conectado a {c.RemoteAddress} por el puerto {c.RemotePort}, usado a menudo por malware para recibir órdenes.",
                    Severity = Severity.Medio,
                    Confidence = "Media",
                    Tag = "conexion-sospechosa"
                };
                h.Actions.Add(new ContainmentAction { Kind = "BloquearIp", Target = c.RemoteAddress, Description = $"Bloquear la IP {c.RemoteAddress}", Recommended = true });

                if (p != null && p.Path != "" && !SafetyGuard.IsCriticalProcess(p.Name))
                {
                    h.Actions.Add(new ContainmentAction { Kind = "TerminarProceso", Target = c.Pid.ToString(), Description = $"Cerrar el proceso {p.Name} (PID {c.Pid})", Recommended = true });
                }

                hallazgos.Add(h);
            }

            // 3) Programas "escuchando" en puertos típicos de puertas traseras
            foreach (ConnectionInfo c in d.Connections.Where(c => c.State.Equals("Listen", StringComparison.OrdinalIgnoreCase) && PuertosPuertaTrasera.Contains(c.LocalPort)))
            {
                ProcInfo? p = Proceso(c.Pid);

                if (EsDeConfianza(p) || !yaReportado.Add("puerta|" + c.LocalPort))
                {
                    continue;
                }

                string quien = p == null ? $"un proceso (PID {c.Pid})" : $"{p.Name} ({p.Path})";
                var h = new IntrusionFinding
                {
                    Title = $"Puerto {c.LocalPort} abierto por un programa desconocido",
                    Description = $"{quien} está esperando conexiones en el puerto {c.LocalPort}, que suele usarse para puertas traseras.",
                    Severity = Severity.Medio,
                    Confidence = "Media",
                    Tag = "puerto-puerta-trasera"
                };

                if (p != null && p.Path != "" && !SafetyGuard.IsCriticalProcess(p.Name))
                {
                    h.Actions.Add(new ContainmentAction { Kind = "TerminarProceso", Target = c.Pid.ToString(), Description = $"Cerrar el proceso {p.Name} (PID {c.Pid})", Recommended = true });
                }

                hallazgos.Add(h);
            }

            // 4) Herramientas de acceso remoto en ejecución
            foreach (ProcInfo p in d.Processes)
            {
                foreach (var herramienta in HerramientasRemotas)
                {
                    if ((herramienta.Patron.IsMatch(p.Name) || herramienta.Patron.IsMatch(p.Path)) && yaReportado.Add("remota|" + herramienta.Nombre))
                    {
                        var h = new IntrusionFinding
                        {
                            Title = $"Herramienta de acceso remoto en ejecución: {herramienta.Nombre}",
                            Description = $"{herramienta.Nombre} está abierto ({p.Path}). Si la instalaste tú, es normal. Si no, alguien pudo instalarla para controlar tu equipo.",
                            Severity = Severity.Medio,
                            Confidence = "Baja",
                            Tag = "herramienta-remota"
                        };

                        if (!SafetyGuard.IsCriticalProcess(p.Name) && p.Path != "")
                        {
                            h.Actions.Add(new ContainmentAction { Kind = "TerminarProceso", Target = p.Pid.ToString(), Description = $"Cerrar {herramienta.Nombre} (PID {p.Pid})", Recommended = false });
                        }

                        hallazgos.Add(h);
                    }
                }
            }

            // 5) Inicios de sesión desde internet (Escritorio remoto o red)
            var desde = DateTime.Now.AddDays(-Math.Max(1, cfg.DiasEventos));
            var sesionesExternas = d.Logons.Where(l => IsPublicIp(l.Ip) && l.Time >= desde).ToList();

            foreach (var grupo in sesionesExternas.GroupBy(l => l.Ip))
            {
                if (!yaReportado.Add("logon|" + grupo.Key))
                {
                    continue;
                }

                LogonEvent ultimo = grupo.OrderByDescending(l => l.Time).First();
                var h = new IntrusionFinding
                {
                    Title = $"Inicio de sesión desde internet ({grupo.Key})",
                    Description = $"Hubo {grupo.Count()} inicio(s) de sesión remoto(s) desde la IP pública {grupo.Key} (último: {ultimo.Time:dd/MM/yyyy HH:mm}, usuario {ultimo.User}). Si no fuiste tú, alguien entró a tu equipo.",
                    Severity = Severity.Alto,
                    Confidence = "Media",
                    Tag = "rdp-publico"
                };
                h.Evidence.AddRange(grupo.OrderByDescending(l => l.Time).Take(5).Select(l => $"{l.Time:dd/MM/yyyy HH:mm} usuario {l.User} tipo {l.Type}"));
                h.Actions.Add(new ContainmentAction { Kind = "BloquearIp", Target = grupo.Key, Description = $"Bloquear la IP {grupo.Key}", Recommended = true });
                hallazgos.Add(h);
            }

            // 6) Intentos de adivinar la contraseña
            var fallosRecientes = d.FailedLogons.Where(l => l.Time >= desde).ToList();

            foreach (var grupo in fallosRecientes.Where(l => l.Ip != "" && l.Ip != "-").GroupBy(l => l.Ip))
            {
                if (grupo.Count() < Math.Max(1, cfg.UmbralFallosInicioSesion))
                {
                    continue;
                }

                bool entroDespues = sesionesExternas.Any(l => l.Ip == grupo.Key);
                bool publica = IsPublicIp(grupo.Key);
                string quitar = "logon|" + grupo.Key;

                if (entroDespues)
                {
                    hallazgos.RemoveAll(x => x.Tag == "rdp-publico" && x.Evidence.Count > 0 && x.Title.Contains(grupo.Key));
                }

                var h = new IntrusionFinding
                {
                    Title = entroDespues
                        ? $"Acceso exitoso tras {grupo.Count()} intentos fallidos desde {grupo.Key}"
                        : $"{grupo.Count()} intentos fallidos de inicio de sesión desde {grupo.Key}",
                    Description = entroDespues
                        ? $"La IP {grupo.Key} falló {grupo.Count()} veces al iniciar sesión y después logró entrar. Es la señal típica de que adivinaron una contraseña."
                        : $"La IP {grupo.Key} intentó iniciar sesión {grupo.Count()} veces sin éxito (ataque de fuerza bruta). No lograron entrar, pero tu equipo está siendo atacado.",
                    Severity = entroDespues ? Severity.Alto : Severity.Medio,
                    Confidence = "Alta",
                    Tag = entroDespues ? "acceso-tras-fuerza-bruta" : "fuerza-bruta"
                };
                h.Evidence.Add($"Usuarios probados: {string.Join(", ", grupo.Select(l => l.User).Distinct().Take(5))}");

                if (publica)
                {
                    h.Actions.Add(new ContainmentAction { Kind = "BloquearIp", Target = grupo.Key, Description = $"Bloquear la IP {grupo.Key}", Recommended = true });
                }

                hallazgos.Add(h);
            }

            // 7) Cuentas nuevas y permisos de administrador
            foreach (LogonEvent u in d.NewUsers)
            {
                hallazgos.Add(new IntrusionFinding
                {
                    Title = $"Se creó una cuenta de usuario nueva: {u.User}",
                    Description = $"El {u.Time:dd/MM/yyyy HH:mm} se creó la cuenta '{u.User}'. Si no la creaste tú, alguien pudo dejarse una forma de volver a entrar.",
                    Severity = Severity.Medio,
                    Confidence = "Baja",
                    Tag = "usuario-nuevo"
                });
            }

            foreach (LogonEvent a in d.AdminAdds)
            {
                hallazgos.Add(new IntrusionFinding
                {
                    Title = "Se agregó una cuenta al grupo de administradores",
                    Description = $"El {a.Time:dd/MM/yyyy HH:mm} se dio permisos de administrador a una cuenta ({a.User}). Si no lo hiciste tú, es una señal fuerte de intrusión.",
                    Severity = Severity.Alto,
                    Confidence = "Media",
                    Tag = "admin-nuevo"
                });
            }

            // 8) Registros de eventos borrados (los atacantes borran sus huellas)
            foreach (DateTime fecha in d.LogsCleared.Take(3))
            {
                hallazgos.Add(new IntrusionFinding
                {
                    Title = "Se borraron los registros de eventos de Windows",
                    Description = $"El {fecha:dd/MM/yyyy HH:mm} se limpió un registro de eventos. Los atacantes lo hacen para borrar sus huellas (aunque también puede haberlo hecho un técnico).",
                    Severity = Severity.Alto,
                    Confidence = "Media",
                    Tag = "logs-borrados"
                });
            }

            // 9) Exclusiones de Microsoft Defender (los virus las agregan para esconderse)
            foreach (string ruta in d.ExclusionPaths.Where(r => !string.IsNullOrWhiteSpace(r)))
            {
                string r = ruta.Trim();
                bool rara = d.Paths.Location(r + "\\x").Puntos > 0 || r.Length <= 3 || r.TrimEnd('\\').EndsWith(":");

                if (rara)
                {
                    var h = new IntrusionFinding
                    {
                        Title = $"Microsoft Defender tiene una exclusión sospechosa: {r}",
                        Description = $"Defender no revisa '{r}'. Los virus agregan exclusiones como esta para esconderse. Si no la agregaste tú, quítala.",
                        Severity = Severity.Alto,
                        Confidence = "Media",
                        Tag = "exclusion-defender"
                    };
                    h.Actions.Add(new ContainmentAction { Kind = "QuitarExclusion", Target = "path|" + r, Description = $"Quitar la exclusión '{r}' de Defender", Recommended = true });
                    hallazgos.Add(h);
                }
            }

            foreach (string ext in d.ExclusionExtensions.Where(e => e.Trim().TrimStart('.').ToLowerInvariant() is "exe" or "dll" or "ps1" or "bat" or "scr" or "js" or "vbs"))
            {
                var h = new IntrusionFinding
                {
                    Title = $"Microsoft Defender ignora todos los archivos .{ext.Trim().TrimStart('.')}",
                    Description = $"Defender tiene una exclusión por extensión (.{ext.Trim().TrimStart('.')}), lo que deja pasar programas sin revisarlos. Es una técnica común del malware.",
                    Severity = Severity.Alto,
                    Confidence = "Media",
                    Tag = "exclusion-defender"
                };
                h.Actions.Add(new ContainmentAction { Kind = "QuitarExclusion", Target = "ext|" + ext.Trim(), Description = $"Quitar la exclusión de la extensión {ext.Trim()}", Recommended = true });
                hallazgos.Add(h);
            }

            // 10) Archivo hosts y proxy
            var hosts = AnalyzeHosts(d.HostsLines);

            if (hosts != null)
            {
                hallazgos.Add(new IntrusionFinding
                {
                    Title = "El archivo hosts fue modificado",
                    Description = hosts.Value.Descripcion,
                    Severity = hosts.Value.Severidad,
                    Confidence = hosts.Value.Severidad == Severity.Alto ? "Media" : "Baja",
                    Tag = "hosts"
                });
            }

            if (d.ProxyServer != "" || d.AutoConfigUrl != "")
            {
                string cual = d.ProxyServer != "" ? $"el proxy {d.ProxyServer}" : $"una configuración automática ({d.AutoConfigUrl})";
                hallazgos.Add(new IntrusionFinding
                {
                    Title = "Tu navegación pasa por un proxy",
                    Description = $"Windows está usando {cual}. En empresas es normal; en un equipo personal puede indicar que alguien intercepta tu tráfico.",
                    Severity = Severity.Medio,
                    Confidence = "Baja",
                    Tag = "proxy"
                });
            }

            foreach (string servicio in d.RemoteServices)
            {
                hallazgos.Add(new IntrusionFinding
                {
                    Title = $"Servicio de administración remota activo: {servicio}",
                    Description = $"El servicio {servicio} permite administrar el equipo desde otra máquina. Si no lo usas, desactívalo.",
                    Severity = Severity.Bajo,
                    Confidence = "Baja",
                    Tag = "servicio-remoto"
                });
            }

            return hallazgos.OrderByDescending(h => h.Severity).ThenBy(h => h.Confidence == "Alta" ? 0 : h.Confidence == "Media" ? 1 : 2).ToList();
        }

        // Resumen: Sin señales, Bajo, Medio o Alto.
        public static string AssessRisk(List<IntrusionFinding> hallazgos)
        {
            int puntos = 0;

            foreach (IntrusionFinding h in hallazgos)
            {
                if (h.Severity == Severity.Alto) puntos += h.Confidence == "Alta" ? 4 : 2;
                else if (h.Severity == Severity.Medio) puntos += 1;
            }

            if (puntos >= 4) return "Alto";
            if (puntos >= 2) return "Medio";
            if (puntos >= 1) return "Bajo";
            return "Sin señales claras";
        }

        private static string NombrePuerto(int puerto)
        {
            switch (puerto)
            {
                case 3389: return "Escritorio remoto";
                case 5900:
                case 5901: return "VNC";
                case 22: return "SSH";
                case 23: return "Telnet";
                case 5985:
                case 5986: return "administración remota de Windows";
                case 445: return "compartir archivos";
                default: return "servicio remoto";
            }
        }

        // ---------------------------------------------------------------
        // Ejecución en el escaneo
        // ---------------------------------------------------------------
        public static void Run(ScanContext ctx)
        {
            if (!ctx.Config.Intrusion.Activo)
            {
                ctx.Note("Intrusión: la detección de intrusiones está desactivada en config.json.");
                return;
            }

            if (!OperatingSystem.IsWindows())
            {
                ctx.Note("Intrusión: la detección de intrusiones solo está disponible en Windows por ahora.");
                return;
            }

            IntrusionInputs datos = IntrusionCollectors.Collect(ctx);
            Apply(ctx, datos);
        }

        // Analiza los datos y registra los resultados (separado para poder probarlo).
        public static void Apply(ScanContext ctx, IntrusionInputs datos)
        {
            List<IntrusionFinding> hallazgos = Analyze(datos, ctx.Config.Intrusion);

            foreach (IntrusionFinding h in hallazgos)
            {
                ctx.Intrusion.Add(h);
                ctx.Add("Posible intrusión: " + h.Title, h.Description + $" (confianza {h.Confidence.ToLowerInvariant()})", h.Severity);
            }

            ctx.IntrusionRisk = AssessRisk(hallazgos);
            ctx.Notes.Add($"Intrusión: riesgo estimado de acceso no autorizado: {ctx.IntrusionRisk}. Se revisaron conexiones, sesiones, cuentas, exclusiones de Defender, archivo hosts y proxy.");

            if (!datos.EventLogReadable)
            {
                ctx.Notes.Add("Intrusión: no se pudieron leer los registros de seguridad de Windows (necesita administrador); no se revisaron inicios de sesión ni cuentas nuevas.");
            }

            ctx.Notes.Add("Intrusión: estas son señales, no pruebas. Una herramienta de acceso remoto o un inicio de sesión pueden ser tuyos; revisa cada hallazgo.");

            if (ctx.Config.Intrusion.ContencionAutomatica && OperatingSystem.IsWindows())
            {
                foreach (ContainmentAction a in hallazgos.Where(h => h.Confidence == "Alta").SelectMany(h => h.Actions).Where(a => a.AutoSafe))
                {
                    IntrusionResponse.Apply(a, ctx.Actions, automatic: true);
                }
            }
        }
    }
}
