using System.Diagnostics;
using System.Text;

namespace snaktools
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            AppConfig config = ConfigService.Load();

            if (args.Contains("--version"))
            {
                Console.WriteLine(AppInfo.Version);
                return 0;
            }

            // Escaneo automático (lo lanza el Programador de tareas de Windows, sin ventanas ni preguntas)
            if (args.Contains("--escaneo-programado"))
            {
                return Scheduler.RunScheduled(config);
            }

            var scanner = new VulnerabilityScanner(config);

            OfferAdminRelaunch();
            UpdateService.CheckOnStartup(config);
            OfferPendingThreats();

            bool salir = false;

            while (!salir)
            {
                ShowMenu();
                string opcion = (Console.ReadLine() ?? "11").Trim();   // si se cierra la entrada, se sale

                switch (opcion)
                {
                    case "1":
                        await RunScan(scanner, ScanType.Equipo);
                        break;

                    case "2":
                        await RunScan(scanner, ScanType.Red);
                        break;

                    case "3":
                        await RunScan(scanner, ScanType.Malware);
                        break;

                    case "4":
                        await RunScan(scanner, ScanType.Intrusion);
                        break;

                    case "5":
                        await RunScan(scanner, ScanType.Total);
                        break;

                    case "6":
                        QuarantineMenu();
                        break;

                    case "7":
                        Scheduler.Menu();
                        break;

                    case "8":
                        OpenLatestReport();
                        break;

                    case "9":
                        OpenReportsFolder();
                        break;

                    case "10":
                        UpdateService.CheckNow(config);
                        break;

                    case "11":
                        salir = true;
                        break;

                    default:
                        Console.WriteLine("Opción inválida.");
                        break;
                }

                if (!salir)
                {
                    ConsoleUi.Pause("Presione Enter para volver al menú...");
                }
            }

            return 0;
        }

        static void ShowMenu()
        {
            Console.Clear();
            ConsoleUi.WriteLine($"snaktools {AppInfo.Version} - detección de vulnerabilidades, virus e intrusiones", ConsoleColor.Cyan);

            if (Environment.IsPrivilegedProcess)
            {
                ConsoleUi.WriteLine("Permisos de administrador: sí", ConsoleColor.Green);
            }
            else
            {
                ConsoleUi.WriteLine("Permisos de administrador: no (algunas revisiones quedarán incompletas)", ConsoleColor.Yellow);
            }

            Console.WriteLine();
            Console.WriteLine("Seleccione una opción:");
            Console.WriteLine(" 1. Escanear vulnerabilidades del equipo.");
            Console.WriteLine(" 2. Escanear vulnerabilidades de la red.");
            Console.WriteLine(" 3. Buscar virus y malware.");
            Console.WriteLine(" 4. Detectar intrusiones y acceso remoto.");
            Console.WriteLine(" 5. Escaneo de seguridad total (todo lo anterior).");
            Console.WriteLine(" 6. Cuarentena y bloqueos (ver, restaurar, deshacer).");
            Console.WriteLine(" 7. Escaneo automático (programar, opcional).");
            Console.WriteLine(" 8. Abrir el último reporte.");
            Console.WriteLine(" 9. Abrir la carpeta de reportes.");
            Console.WriteLine("10. Buscar actualizaciones de snaktools.");
            Console.WriteLine("11. Salir del programa.");
            Console.Write("Opción: ");
        }

        // Si no es administrador, ofrece reiniciar el programa con permisos elevados (solo Windows).
        static void OfferAdminRelaunch()
        {
            if (!OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            {
                return;
            }

            string? exe = Environment.ProcessPath;

            // Si se está ejecutando con "dotnet run", no se puede relanzar.
            if (exe == null || Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Console.WriteLine("snaktools no se está ejecutando como administrador. Algunas revisiones quedarán incompletas.");

            if (ConsoleUi.AskYesNo("¿Desea reiniciarlo con permisos de administrador?"))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
                    Environment.Exit(0);
                }
                catch (Exception)
                {
                    Console.WriteLine("No se obtuvieron los permisos (se canceló la solicitud). Se continúa sin ellos.");
                    ConsoleUi.Pause();
                }
            }
        }

        // Amenazas que dejó pendientes el último escaneo automático.
        static void OfferPendingThreats()
        {
            AppState estado = StateStore.Load();
            List<ThreatCandidate> pendientes = estado.PendingThreats.Where(t => File.Exists(t.Path)).ToList();

            if (pendientes.Count != estado.PendingThreats.Count)
            {
                estado.PendingThreats = pendientes;
                StateStore.Save(estado);
            }

            if (pendientes.Count == 0)
            {
                return;
            }

            Console.WriteLine();
            ConsoleUi.WriteLine($"El último escaneo automático dejó {pendientes.Count} amenaza(s) pendiente(s) de revisar.", ConsoleColor.Yellow);

            if (ConsoleUi.AskYesNo("¿Quieres revisarlas ahora?"))
            {
                var log = new List<ActionRecord>();
                ThreatResponse.Run(pendientes, log);

                estado = StateStore.Load();
                estado.PendingThreats = estado.PendingThreats.Where(t => File.Exists(t.Path)).ToList();
                StateStore.Save(estado);
            }
        }

        static bool ConfirmNetworkScan()
        {
            Console.WriteLine();
            Console.WriteLine("El escaneo de red prueba los dispositivos de tu red local (ping y algunos puertos comunes).");
            Console.WriteLine("Úsalo solo en una red que sea tuya o en la que tengas permiso para hacerlo.");
            return ConsoleUi.AskYesNo("¿Desea continuar?");
        }

        static async Task RunScan(VulnerabilityScanner scanner, ScanType kind)
        {
            bool usaRed = kind == ScanType.Red || kind == ScanType.Total;
            bool usaEquipo = kind == ScanType.Equipo || kind == ScanType.Total;
            bool usaMalware = kind == ScanType.Malware || kind == ScanType.Total;

            if (usaRed && !ConfirmNetworkScan())
            {
                return;
            }

            Console.WriteLine();

            if (!Environment.IsPrivilegedProcess)
            {
                ConsoleUi.WriteLine("Aviso: no estás ejecutando como administrador/root. Algunas revisiones pueden quedar incompletas.", ConsoleColor.Yellow);
            }

            if (usaEquipo && scanner.Config.RevisarCve)
            {
                ConsoleUi.WriteLine("La consulta de vulnerabilidades (CVE) puede tardar unos minutos la primera vez; los resultados se guardan para que las próximas veces sea rápido.", ConsoleColor.DarkGray);
            }

            if (usaMalware && scanner.Config.Malware.UsarDefender)
            {
                ConsoleUi.WriteLine("La búsqueda de virus incluye un escaneo rápido de Microsoft Defender, que puede tardar varios minutos.", ConsoleColor.DarkGray);
            }

            try
            {
                // El escaneo corre en segundo plano y la consola va mostrando el progreso.
                await Task.Run(() => scanner.Scan(kind, ConsoleUi.Progress));
                ShowResults(scanner);

                Report? informe = scanner.LastReport;

                if (informe != null)
                {
                    // Las amenazas se atienden con tu confirmación, una por una o todas.
                    if (informe.Threats.Count > 0)
                    {
                        ThreatResponse.Run(informe.Threats, informe.Actions);
                    }

                    // Contención inmediata (bloquear al intruso), también con tu confirmación.
                    if (informe.Intrusion.Any(h => h.Actions.Count > 0))
                    {
                        IntrusionResponse.Run(informe.Intrusion, informe.Actions);
                    }
                }

                // El reporte se genera al final para incluir todo lo que se hizo.
                scanner.GenerateReport();
                scanner.NotifyUser();

                Console.WriteLine();
                Console.WriteLine($"Reporte guardado en: {scanner.ReportPath}");

                if (scanner.HtmlReportPath != "")
                {
                    Console.WriteLine($"Reporte HTML: {scanner.HtmlReportPath}");
                }

                if (scanner.Config.AbrirReporteAlTerminar)
                {
                    string abrir = scanner.HtmlReportPath != "" ? scanner.HtmlReportPath : scanner.ReportPath;
                    ActionsMenu.OpenTarget(abrir);
                }

                bool hayVulnerabilidades = informe != null && informe.Vulnerabilities.Any(v => !v.Name.StartsWith("Posible intrusión") && !v.Name.Contains(": ") || v.Name.StartsWith("CVE") || v.Name.StartsWith("Puerto") || v.Name.StartsWith("Firewall"));

                if ((usaEquipo || kind == ScanType.Red) && hayVulnerabilidades)
                {
                    Console.WriteLine();
                    if (ConsoleUi.AskYesNo("¿Desea ver las opciones para corregir las vulnerabilidades (actualizar, firewall, router)?"))
                    {
                        scanner.TakeActionOnVulnerabilities();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                ConsoleUi.WriteLine($"El escaneo falló: {ex.Message}", ConsoleColor.Red);
            }
        }

        static void ShowResults(VulnerabilityScanner scanner)
        {
            Report? r = scanner.LastReport;

            if (r == null)
            {
                return;
            }

            Console.WriteLine();
            ConsoleUi.WriteLine($"Escaneo completado en {r.DurationSeconds} s ({r.KindName}).", ConsoleColor.Green);

            if (r.IntrusionRisk != "")
            {
                ConsoleColor color = r.IntrusionRisk == "Alto" ? ConsoleColor.Red : r.IntrusionRisk == "Medio" ? ConsoleColor.Yellow : ConsoleColor.Green;
                ConsoleUi.WriteLine($"Riesgo estimado de intrusión: {r.IntrusionRisk}", color);
            }

            if (r.Vulnerabilities.Count == 0)
            {
                ConsoleUi.WriteLine("No se encontró nada con las revisiones actuales.", ConsoleColor.Green);
            }
            else
            {
                Console.WriteLine($"Hallazgos: {r.TotalVulnerabilities}");
                Console.WriteLine();

                foreach (Vulnerability v in r.Vulnerabilities)
                {
                    ConsoleUi.Write($"[{Severity.Name(v.SeverityLevel)}] ", ConsoleUi.SeverityColor(v.SeverityLevel));
                    Console.WriteLine(v.Name);
                    Console.WriteLine($"    {v.Description}");
                }
            }

            if (r.HasPreviousScan)
            {
                Console.WriteLine();
                Console.WriteLine("Comparado con el escaneo anterior:");
                ConsoleUi.WriteLine($"  Nuevas: {r.NewVulnerabilities.Count}", r.NewVulnerabilities.Count > 0 ? ConsoleColor.Red : ConsoleColor.Gray);
                ConsoleUi.WriteLine($"  Resueltas: {r.ResolvedVulnerabilities.Count}", r.ResolvedVulnerabilities.Count > 0 ? ConsoleColor.Green : ConsoleColor.Gray);
            }

            List<string> urgentes = r.Recommendations.Where(x => x.StartsWith("URGENTE")).ToList();

            if (urgentes.Count > 0)
            {
                Console.WriteLine();
                ConsoleUi.WriteLine("Medidas urgentes recomendadas:", ConsoleColor.Red);

                foreach (string u in urgentes)
                {
                    Console.WriteLine("  - " + u.Replace("URGENTE: ", ""));
                }
            }

            if (r.Notes.Count > 0)
            {
                Console.WriteLine();

                foreach (string nota in r.Notes)
                {
                    ConsoleUi.WriteLine($"Nota: {nota}", ConsoleColor.DarkGray);
                }
            }
        }

        // ---------------------------------------------------------------
        // Cuarentena y bloqueos
        // ---------------------------------------------------------------
        static void QuarantineMenu()
        {
            bool volver = false;
            var log = new List<ActionRecord>();

            while (!volver)
            {
                Console.WriteLine();
                Console.WriteLine("Cuarentena y bloqueos");
                Console.WriteLine("1. Ver lo que hay en cuarentena");
                Console.WriteLine("2. Restaurar un elemento a su lugar original");
                Console.WriteLine("3. Eliminar un elemento definitivamente");
                Console.WriteLine("4. Ver y deshacer bloqueos de red y cambios de contención");
                Console.WriteLine("5. Volver");
                Console.Write("Opción: ");

                switch ((Console.ReadLine() ?? "5").Trim())
                {
                    case "1":
                        ListQuarantine();
                        break;

                    case "2":
                        ChooseQuarantineItem("restaurar", id =>
                        {
                            bool ok = Quarantine.Restore(id, out string mensaje);
                            ConsoleUi.WriteLine(mensaje, ok ? ConsoleColor.Green : ConsoleColor.Yellow);
                        });
                        break;

                    case "3":
                        ChooseQuarantineItem("eliminar definitivamente", id =>
                        {
                            if (ConsoleUi.AskYesNo("Esto borra el archivo para siempre y no se puede deshacer. ¿Seguro?"))
                            {
                                bool ok = Quarantine.DeletePermanently(id, out string mensaje);
                                ConsoleUi.WriteLine(mensaje, ok ? ConsoleColor.Green : ConsoleColor.Yellow);
                            }
                        });
                        break;

                    case "4":
                        IntrusionResponse.UndoMenu(log);
                        break;

                    case "5":
                        volver = true;
                        break;

                    default:
                        Console.WriteLine("Opción inválida.");
                        break;
                }
            }
        }

        static List<QuarantineItem> CurrentQuarantine()
        {
            return Quarantine.List().Where(i => i.Status == "En cuarentena").ToList();
        }

        static void ListQuarantine()
        {
            List<QuarantineItem> items = CurrentQuarantine();
            Console.WriteLine();

            if (items.Count == 0)
            {
                Console.WriteLine("La cuarentena está vacía.");
                return;
            }

            for (int i = 0; i < items.Count; i++)
            {
                Console.WriteLine($"{i + 1}. {items[i].Name}  ({items[i].DateUtc.ToLocalTime():dd/MM/yyyy HH:mm})");
                Console.WriteLine($"     Estaba en: {items[i].OriginalPath}");
                Console.WriteLine($"     Motivo: {items[i].Reason}");
            }
        }

        static void ChooseQuarantineItem(string verbo, Action<string> accion)
        {
            List<QuarantineItem> items = CurrentQuarantine();

            if (items.Count == 0)
            {
                Console.WriteLine("La cuarentena está vacía.");
                return;
            }

            ListQuarantine();
            Console.Write($"Número del elemento a {verbo} (Enter para cancelar): ");

            if (int.TryParse((Console.ReadLine() ?? "").Trim(), out int n) && n >= 1 && n <= items.Count)
            {
                accion(items[n - 1].Id);
            }
        }

        static void OpenLatestReport()
        {
            string? ruta = ReportHistory.GetLatestReport();

            if (ruta == null)
            {
                Console.WriteLine("Todavía no hay reportes. Haz un escaneo primero.");
            }
            else
            {
                Console.WriteLine($"Abriendo {ruta} ...");
                ActionsMenu.OpenTarget(ruta);
            }
        }

        static void OpenReportsFolder()
        {
            try
            {
                Directory.CreateDirectory(AppPaths.ReportsDir);
                ActionsMenu.OpenTarget(AppPaths.ReportsDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"No se pudo abrir la carpeta de reportes: {ex.Message}");
            }
        }
    }
}
