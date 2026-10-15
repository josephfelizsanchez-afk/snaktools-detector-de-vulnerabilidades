using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace snaktools
{
    // Lo que el programa cambió para contener una intrusión (para poder deshacerlo).
    class ContainmentRecord
    {
        public DateTime DateUtc { get; set; }
        public string Kind { get; set; } = "";
        public string Target { get; set; } = "";
        public string Previous { get; set; } = "";
        public bool Undone { get; set; }
    }

    class ContainmentLog
    {
        public List<ContainmentRecord> Items { get; set; } = new List<ContainmentRecord>();
    }

    // Bloquea o frena una intrusión. Todas las acciones se pueden deshacer y nunca tocan archivos.
    internal static class IntrusionResponse
    {
        public const string RulePrefix = "snaktools-bloqueo-";

        // Argumentos de netsh para bloquear una IP (en una función aparte para poder probarlos).
        public static List<string[]> BuildBlockCommands(string ip)
        {
            string nombre = RulePrefix + ip;
            return new List<string[]>
            {
                new[] { "advfirewall", "firewall", "add", "rule", "name=" + nombre + "-entrada", "dir=in", "action=block", "remoteip=" + ip },
                new[] { "advfirewall", "firewall", "add", "rule", "name=" + nombre + "-salida", "dir=out", "action=block", "remoteip=" + ip }
            };
        }

        // Solo se bloquean IP públicas válidas: nunca la red local, el router ni direcciones especiales.
        public static bool CanBlockIp(string ip, out string motivo)
        {
            motivo = "";

            if (!IPAddress.TryParse(ip, out _))
            {
                motivo = "No es una dirección IP válida.";
                return false;
            }

            if (!IntrusionChecks.IsPublicIp(ip))
            {
                motivo = "Es una dirección de tu red local o especial; bloquearla podría dejarte sin conexión.";
                return false;
            }

            return true;
        }

        public static bool Apply(ContainmentAction accion, List<ActionRecord> log, bool automatic = false)
        {
            string quien = automatic ? "automático" : "con tu confirmación";

            try
            {
                switch (accion.Kind)
                {
                    case "BloquearIp":
                        if (!CanBlockIp(accion.Target, out string motivo))
                        {
                            log.Add(new ActionRecord { Action = "Bloquear IP", Target = accion.Target, Detail = "No se bloqueó: " + motivo, Success = false });
                            return false;
                        }

                        foreach (string[] args in BuildBlockCommands(accion.Target))
                        {
                            CommandRunner.Run("netsh", args, 20000);
                        }

                        SaveRecord("BloquearIp", accion.Target, "");
                        log.Add(new ActionRecord { Action = "Bloquear IP", Target = accion.Target, Detail = $"Regla de firewall creada ({quien}). Se puede deshacer desde el menú de bloqueos." });
                        return true;

                    case "TerminarProceso":
                        return KillProcess(accion, log, quien);

                    case "DesactivarRdp":
                        return DisableRdp(log, quien);

                    case "QuitarExclusion":
                        return RemoveExclusion(accion, log, quien);

                    case "DesactivarInvitado":
                        CommandRunner.Run("net", new[] { "user", "guest", "/active:no" }, 20000);
                        SaveRecord("DesactivarInvitado", "guest", "yes");
                        log.Add(new ActionRecord { Action = "Desactivar cuenta de invitado", Target = "guest", Detail = quien });
                        return true;

                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                log.Add(new ActionRecord { Action = accion.Kind, Target = accion.Target, Detail = "Falló: " + ex.Message, Success = false });
                return false;
            }
        }

        private static bool KillProcess(ContainmentAction accion, List<ActionRecord> log, string quien)
        {
            if (!int.TryParse(accion.Target, out int pid))
            {
                return false;
            }

            using Process p = Process.GetProcessById(pid);

            if (SafetyGuard.IsCriticalProcess(p.ProcessName) || pid == Environment.ProcessId)
            {
                log.Add(new ActionRecord { Action = "Cerrar proceso", Target = p.ProcessName, Detail = "Es un proceso crítico; no se cierra.", Success = false });
                return false;
            }

            string nombre = p.ProcessName;
            p.Kill(true);
            p.WaitForExit(5000);
            log.Add(new ActionRecord { Action = "Cerrar proceso", Target = $"{nombre} (PID {pid})", Detail = quien });
            return true;
        }

        private static bool DisableRdp(List<ActionRecord> log, string quien)
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            return DisableRdpWindows(log, quien);
        }

        [SupportedOSPlatform("windows")]
        private static bool DisableRdpWindows(List<ActionRecord> log, string quien)
        {
            using RegistryKey? k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", writable: true);

            if (k == null)
            {
                return false;
            }

            string anterior = k.GetValue("fDenyTSConnections")?.ToString() ?? "0";
            k.SetValue("fDenyTSConnections", 1, RegistryValueKind.DWord);
            SaveRecord("DesactivarRdp", "RDP", anterior);
            log.Add(new ActionRecord { Action = "Desactivar Escritorio remoto", Target = "RDP", Detail = $"Se desactivó ({quien}). Se puede reactivar desde el menú de bloqueos." });
            return true;
        }

        private static bool RemoveExclusion(ContainmentAction accion, List<ActionRecord> log, string quien)
        {
            string[] partes = accion.Target.Split('|', 2);

            if (partes.Length != 2 || partes[1].Trim() == "")
            {
                return false;
            }

            string parametro = partes[0] == "ext" ? "ExclusionExtension" : "ExclusionPath";
            CommandRunner.PowerShell($"Remove-MpPreference -{parametro} {PersistenceCleaner.Quote(partes[1])}", 30000);
            SaveRecord("QuitarExclusion", accion.Target, "");
            log.Add(new ActionRecord { Action = "Quitar exclusión de Defender", Target = partes[1], Detail = quien });
            return true;
        }

        private static void SaveRecord(string tipo, string destino, string anterior)
        {
            ContainmentLog registro = JsonStore.Load<ContainmentLog>(AppPaths.ContainmentLogFile);
            registro.Items.Add(new ContainmentRecord { DateUtc = DateTime.UtcNow, Kind = tipo, Target = destino, Previous = anterior });
            JsonStore.Save(AppPaths.ContainmentLogFile, registro);
        }

        // ---------------------------------------------------------------
        // Pantalla interactiva: respuesta inmediata
        // ---------------------------------------------------------------
        public static void Run(List<IntrusionFinding> hallazgos, List<ActionRecord> log)
        {
            var acciones = hallazgos
                .Where(h => h.Actions.Count > 0)
                .SelectMany(h => h.Actions.Select(a => (Hallazgo: h, Accion: a)))
                .GroupBy(x => x.Accion.Kind + "|" + x.Accion.Target)
                .Select(g => g.First())
                .ToList();

            if (acciones.Count == 0)
            {
                return;
            }

            Console.WriteLine();
            ConsoleUi.WriteLine("=== RESPUESTA A LA INTRUSIÓN ===", ConsoleColor.Red);
            Console.WriteLine("Estas acciones frenan el acceso de inmediato. Todas se pueden deshacer y ninguna borra archivos.");
            Console.WriteLine();

            for (int i = 0; i < acciones.Count; i++)
            {
                string marca = acciones[i].Accion.Recommended ? " (recomendada)" : "";
                Console.WriteLine($"{i + 1}. {acciones[i].Accion.Description}{marca}");
                Console.WriteLine($"     Motivo: {acciones[i].Hallazgo.Title}");
            }

            Console.WriteLine();
            Console.WriteLine("Escribe los números a aplicar (ejemplo: 1,3), 'recomendadas' para aplicar las recomendadas, o Enter para no hacer nada.");
            Console.Write("> ");
            string respuesta = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();

            var elegidas = new List<ContainmentAction>();

            if (respuesta == "recomendadas" || respuesta == "recomendada")
            {
                elegidas.AddRange(acciones.Select(a => a.Accion).Where(a => a.Recommended));
            }
            else if (respuesta != "")
            {
                foreach (string trozo in respuesta.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (int.TryParse(trozo, out int n) && n >= 1 && n <= acciones.Count)
                    {
                        elegidas.Add(acciones[n - 1].Accion);
                    }
                }
            }

            if (elegidas.Count == 0)
            {
                Console.WriteLine("No se aplicó ninguna acción.");
                return;
            }

            if (!ConsoleUi.AskYesNo($"¿Aplicar {elegidas.Count} acción(es) ahora?"))
            {
                Console.WriteLine("No se aplicó ninguna acción.");
                return;
            }

            foreach (ContainmentAction a in elegidas)
            {
                bool ok = Apply(a, log);
                ConsoleUi.WriteLine((ok ? "Hecho: " : "No se pudo: ") + a.Description, ok ? ConsoleColor.Green : ConsoleColor.Yellow);
            }
        }

        // ---------------------------------------------------------------
        // Ver y deshacer lo que se aplicó
        // ---------------------------------------------------------------
        public static void UndoMenu(List<ActionRecord> log)
        {
            ContainmentLog registro = JsonStore.Load<ContainmentLog>(AppPaths.ContainmentLogFile);
            var activos = registro.Items.Where(i => !i.Undone).ToList();

            Console.WriteLine();

            if (activos.Count == 0)
            {
                Console.WriteLine("No hay bloqueos ni cambios de contención activos.");
                return;
            }

            for (int i = 0; i < activos.Count; i++)
            {
                Console.WriteLine($"{i + 1}. {activos[i].DateUtc.ToLocalTime():dd/MM/yyyy HH:mm}  {Describe(activos[i])}");
            }

            Console.WriteLine("Escribe el número que quieres deshacer, o Enter para volver.");
            Console.Write("> ");

            if (int.TryParse((Console.ReadLine() ?? "").Trim(), out int n) && n >= 1 && n <= activos.Count)
            {
                ContainmentRecord r = activos[n - 1];
                bool ok = Undo(r, log);

                if (ok)
                {
                    r.Undone = true;
                    JsonStore.Save(AppPaths.ContainmentLogFile, registro);
                }

                ConsoleUi.WriteLine(ok ? "Deshecho." : "No se pudo deshacer.", ok ? ConsoleColor.Green : ConsoleColor.Yellow);
            }
        }

        private static string Describe(ContainmentRecord r)
        {
            switch (r.Kind)
            {
                case "BloquearIp": return "IP bloqueada: " + r.Target;
                case "DesactivarRdp": return "Escritorio remoto desactivado";
                case "QuitarExclusion": return "Exclusión de Defender quitada: " + r.Target;
                case "DesactivarInvitado": return "Cuenta de invitado desactivada";
                default: return r.Kind + " " + r.Target;
            }
        }

        private static bool Undo(ContainmentRecord r, List<ActionRecord> log)
        {
            try
            {
                switch (r.Kind)
                {
                    case "BloquearIp":
                        if (!IPAddress.TryParse(r.Target, out _)) return false;
                        CommandRunner.Run("netsh", new[] { "advfirewall", "firewall", "delete", "rule", "name=" + RulePrefix + r.Target + "-entrada" }, 20000);
                        CommandRunner.Run("netsh", new[] { "advfirewall", "firewall", "delete", "rule", "name=" + RulePrefix + r.Target + "-salida" }, 20000);
                        break;

                    case "DesactivarRdp":
                        if (!OperatingSystem.IsWindows()) return false;
                        EnableRdp(r.Previous);
                        break;

                    case "QuitarExclusion":
                        string[] partes = r.Target.Split('|', 2);
                        string parametro = partes[0] == "ext" ? "ExclusionExtension" : "ExclusionPath";
                        CommandRunner.PowerShell($"Add-MpPreference -{parametro} {PersistenceCleaner.Quote(partes[1])}", 30000);
                        break;

                    case "DesactivarInvitado":
                        CommandRunner.Run("net", new[] { "user", "guest", "/active:yes" }, 20000);
                        break;

                    default:
                        return false;
                }

                log.Add(new ActionRecord { Action = "Deshacer", Target = Describe(r), Detail = "Se revirtió el cambio." });
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        [SupportedOSPlatform("windows")]
        private static void EnableRdp(string anterior)
        {
            using RegistryKey? k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", writable: true);
            k?.SetValue("fDenyTSConnections", int.TryParse(anterior, out int v) ? v : 0, RegistryValueKind.DWord);
        }
    }
}
