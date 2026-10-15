using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace snaktools
{
    // Escaneo automático opcional: se programa solo si el usuario lo pide.
    // Corre con prioridad baja y solo cuando el equipo está sin uso, para no saturarlo.
    internal static class Scheduler
    {
        public const string TaskName = "snaktools-escaneo-automatico";
        private static readonly string[] Dias = { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };
        private static readonly string[] DiasEs = { "lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo" };

        [DllImport("kernel32.dll")]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        public static bool IsValidTime(string texto)
        {
            return Regex.IsMatch(texto, @"^([01]?\d|2[0-3]):[0-5]\d$");
        }

        // Crea el script de PowerShell que registra la tarea (separado para poder revisarlo en pruebas).
        public static string BuildRegisterScript(string exe, string frecuencia, string hora, string dia, bool maximo)
        {
            string[] hm = hora.Split(':');
            int h = int.Parse(hm[0]);
            int m = int.Parse(hm[1]);
            string cuando = $"([datetime]::Today.AddHours({h}).AddMinutes({m}))";
            string disparador = frecuencia == "semanal"
                ? $"New-ScheduledTaskTrigger -Weekly -DaysOfWeek {dia} -At {cuando}"
                : $"New-ScheduledTaskTrigger -Daily -At {cuando}";

            return
                $"$a = New-ScheduledTaskAction -Execute {PersistenceCleaner.Quote(exe)} -Argument '--escaneo-programado'; " +
                $"$t = {disparador}; " +
                "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfIdle -IdleDuration (New-TimeSpan -Minutes 5) " +
                "-IdleWaitTimeout (New-TimeSpan -Hours 2) -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew; " +
                "$p = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel " + (maximo ? "Highest" : "Limited") + "; " +
                $"Register-ScheduledTask -TaskName '{TaskName}' -Action $a -Trigger $t -Settings $s -Principal $p " +
                "-Description 'Escaneo de seguridad de snaktools (prioridad baja, solo con el equipo sin uso)' -Force | Out-Null; 'ok'";
        }

        public static string Status()
        {
            if (!OperatingSystem.IsWindows())
            {
                return "El escaneo programado solo está disponible en Windows.";
            }

            string estado = CommandRunner.PowerShell($"(Get-ScheduledTask -TaskName '{TaskName}' -ErrorAction SilentlyContinue).State", 20000);

            if (estado == "")
            {
                return "No hay ningún escaneo automático programado.";
            }

            string proximo = CommandRunner.PowerShell($"(Get-ScheduledTaskInfo -TaskName '{TaskName}' -ErrorAction SilentlyContinue).NextRunTime", 20000);
            return $"Escaneo automático programado (estado: {estado}). Próxima ejecución: {(proximo == "" ? "sin fecha" : proximo)}.";
        }

        public static void Menu()
        {
            Console.WriteLine();
            Console.WriteLine("Escaneo automático (opcional)");
            Console.WriteLine("Por defecto snaktools solo escanea cuando tú lo pides. Aquí puedes programar un escaneo automático.");
            Console.WriteLine("Corre con prioridad baja y solo cuando el equipo está sin uso. No elimina nada solo: al terminar te avisa y tú decides.");
            Console.WriteLine();
            Console.WriteLine(Status());
            Console.WriteLine();
            Console.WriteLine("1. Programar un escaneo diario");
            Console.WriteLine("2. Programar un escaneo semanal");
            Console.WriteLine("3. Quitar la programación");
            Console.WriteLine("4. Volver");
            Console.Write("Opción: ");

            switch ((Console.ReadLine() ?? "").Trim())
            {
                case "1":
                    Register("diario");
                    break;
                case "2":
                    Register("semanal");
                    break;
                case "3":
                    Remove();
                    break;
            }
        }

        private static void Register(string frecuencia)
        {
            if (!OperatingSystem.IsWindows())
            {
                Console.WriteLine("El escaneo programado solo está disponible en Windows.");
                return;
            }

            string? exe = Environment.ProcessPath;

            if (exe == null || Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Para programar el escaneo necesitas usar el ejecutable snaktools.exe (no 'dotnet run').");
                return;
            }

            string hora = "";

            while (hora == "")
            {
                Console.Write("¿A qué hora? (formato 24 horas, por ejemplo 14:00; Enter = 14:00): ");
                string entrada = (Console.ReadLine() ?? "").Trim();
                entrada = entrada == "" ? "14:00" : entrada;

                if (IsValidTime(entrada))
                {
                    hora = entrada;
                }
                else
                {
                    Console.WriteLine("Hora no válida.");
                }
            }

            string dia = "Monday";

            if (frecuencia == "semanal")
            {
                for (int i = 0; i < Dias.Length; i++)
                {
                    Console.WriteLine($"{i + 1}. {DiasEs[i]}");
                }

                Console.Write("¿Qué día? (1-7): ");

                if (int.TryParse((Console.ReadLine() ?? "").Trim(), out int n) && n >= 1 && n <= 7)
                {
                    dia = Dias[n - 1];
                }
                else
                {
                    Console.WriteLine("Día no válido; se usará el lunes.");
                }
            }

            string resultado = CommandRunner.PowerShell(BuildRegisterScript(exe, frecuencia, hora, dia, Environment.IsPrivilegedProcess), 60000);

            if (resultado.Contains("ok"))
            {
                ConsoleUi.WriteLine($"Listo. {Status()}", ConsoleColor.Green);
            }
            else
            {
                ConsoleUi.WriteLine("No se pudo programar la tarea (prueba abriendo snaktools como administrador).", ConsoleColor.Yellow);
            }
        }

        private static void Remove()
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            CommandRunner.PowerShell($"Unregister-ScheduledTask -TaskName '{TaskName}' -Confirm:$false -ErrorAction SilentlyContinue", 30000);
            Console.WriteLine("Se quitó la programación (si existía).");
        }

        // Lo que ocurre cuando Windows ejecuta el escaneo automático (sin preguntas ni ventanas).
        public static int RunScheduled(AppConfig cfg)
        {
            // Prioridad de fondo: menos CPU, menos disco y menos memoria que el resto de programas.
            Throttle.Enabled = true;
            Throttle.SleepMs = Math.Max(0, cfg.Malware.PausaBajoConsumoMs);

            try
            {
                if (OperatingSystem.IsWindows())
                {
                    SetPriorityClass(GetCurrentProcess(), 0x00100000);   // PROCESS_MODE_BACKGROUND_BEGIN
                }

                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
            }
            catch (Exception)
            {
            }

            var scanner = new VulnerabilityScanner(cfg);
            scanner.Scan(ScanType.TotalSinRed, null, lowImpact: true);

            Report? informe = scanner.LastReport;

            if (informe != null)
            {
                informe.Actions.Add(new ActionRecord
                {
                    Action = "Escaneo automático",
                    Target = "Equipo",
                    Detail = "No se eliminó ni se cambió nada: las amenazas quedan pendientes hasta que tú decidas qué hacer con ellas."
                });
            }

            scanner.GenerateReport();

            AppState estado = StateStore.Load();
            estado.LastScheduledRunUtc = DateTime.UtcNow;
            estado.PendingThreats = informe?.Threats ?? new List<ThreatCandidate>();
            StateStore.Save(estado);

            int amenazas = informe?.Threats.Count ?? 0;
            int total = informe?.TotalVulnerabilities ?? 0;
            string intrusion = informe?.IntrusionRisk ?? "";
            string texto = $"Escaneo terminado: {amenazas} amenaza(s), {total} hallazgo(s) en total" +
                           (intrusion != "" ? $", riesgo de intrusión: {intrusion}" : "") + ". Haz clic para ver el resultado.";

            string abrir = scanner.HtmlReportPath != "" ? scanner.HtmlReportPath : scanner.ReportPath;
            new Notification().ShowClickable(texto, abrir, wait: true);
            return 0;
        }
    }
}
