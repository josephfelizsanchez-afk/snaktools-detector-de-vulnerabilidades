using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace snaktools
{
    // Recolecta datos de Windows para detectar intrusiones. Las funciones Parse* se pueden probar con datos de ejemplo.
    internal static class IntrusionCollectors
    {
        private static List<JsonElement> Array(JsonElement raiz, string nombre)
        {
            var lista = new List<JsonElement>();

            if (raiz.ValueKind == JsonValueKind.Object && raiz.TryGetProperty(nombre, out JsonElement e))
            {
                if (e.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement x in e.EnumerateArray()) lista.Add(x.Clone());
                }
                else if (e.ValueKind == JsonValueKind.Object)
                {
                    lista.Add(e.Clone());
                }
            }

            return lista;
        }

        private static string Str(JsonElement e, string nombre)
        {
            if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(nombre, out JsonElement v))
            {
                if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
                if (v.ValueKind == JsonValueKind.Number) return v.GetRawText();
            }

            return "";
        }

        public static List<ConnectionInfo> ParseConnections(string json)
        {
            var lista = new List<ConnectionInfo>();

            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                IEnumerable<JsonElement> items = doc.RootElement.ValueKind == JsonValueKind.Array
                    ? doc.RootElement.EnumerateArray().Select(x => x.Clone()).ToList()
                    : new List<JsonElement> { doc.RootElement.Clone() };

                foreach (JsonElement e in items)
                {
                    lista.Add(new ConnectionInfo
                    {
                        LocalAddress = Str(e, "LocalAddress"),
                        LocalPort = int.TryParse(Str(e, "LocalPort"), out int lp) ? lp : 0,
                        RemoteAddress = Str(e, "RemoteAddress"),
                        RemotePort = int.TryParse(Str(e, "RemotePort"), out int rp) ? rp : 0,
                        State = Str(e, "State"),
                        Pid = int.TryParse(Str(e, "OwningProcess"), out int pid) ? pid : 0
                    });
                }
            }
            catch (JsonException)
            {
            }

            return lista;
        }

        private static DateTime ParseTime(string texto)
        {
            return DateTime.TryParse(texto, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime t)
                ? t.ToLocalTime()
                : DateTime.MinValue;
        }

        // Interpreta el resultado del script de eventos de seguridad.
        public static void ParseEvents(string json, IntrusionInputs d)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement raiz = doc.RootElement;

                d.EventLogReadable = !raiz.TryGetProperty("ok", out JsonElement ok) || ok.ValueKind != JsonValueKind.False;

                d.Logons = Array(raiz, "logons").Select(e => new LogonEvent { Time = ParseTime(Str(e, "Time")), User = Str(e, "User"), Ip = Str(e, "Ip"), Type = Str(e, "Type") }).ToList();
                d.FailedLogons = Array(raiz, "failed").Select(e => new LogonEvent { Time = ParseTime(Str(e, "Time")), User = Str(e, "User"), Ip = Str(e, "Ip") }).ToList();
                d.NewUsers = Array(raiz, "users").Select(e => new LogonEvent { Time = ParseTime(Str(e, "Time")), User = Str(e, "User") }).ToList();
                d.AdminAdds = Array(raiz, "admins").Select(e => new LogonEvent { Time = ParseTime(Str(e, "Time")), User = Str(e, "User") }).ToList();
                d.LogsCleared = Array(raiz, "cleared").Select(e => ParseTime(Str(e, "Time"))).ToList();
            }
            catch (JsonException)
            {
                d.EventLogReadable = false;
            }
        }

        public static void ParseExclusions(string json, IntrusionInputs d)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);

                List<string> Lista(string nombre) => Array(doc.RootElement, nombre)
                    .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "")
                    .Where(s => s != "" && !s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                d.ExclusionPaths = Lista("paths");
                d.ExclusionProcesses = Lista("processes");
                d.ExclusionExtensions = Lista("extensions");
            }
            catch (JsonException)
            {
            }
        }

        [SupportedOSPlatform("windows")]
        public static IntrusionInputs Collect(ScanContext ctx)
        {
            IntrusionConfig cfg = ctx.Config.Intrusion;
            var d = new IntrusionInputs { Paths = PathContext.FromEnvironment() };

            ctx.SubProgress?.Invoke("Intrusión: conexiones de red");
            d.Processes = WindowsCollectors.GetProcesses(ctx);
            d.Connections = ParseConnections(CommandRunner.PowerShell(
                "$r = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Established','Listen' } | " +
                "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={[string]$_.State}},OwningProcess; " +
                "ConvertTo-Json -InputObject @($r) -Compress", 60000));

            ctx.SubProgress?.Invoke("Intrusión: registros de seguridad");
            int dias = Math.Max(1, cfg.DiasEventos);

            string script =
                "$ok = $true; try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null } catch { $ok = $false }; " +
                "function Datos($ev) { $x = [xml]$ev.ToXml(); $h = @{}; foreach ($n in $x.Event.EventData.Data) { $h[$n.Name] = $n.'#text' }; $h }; " +
                "$logons = @(); $failed = @(); $users = @(); $admins = @(); $cleared = @(); " +
                "if ($ok) { " +
                "  $s = (Get-Date).AddDays(-" + dias + "); $s30 = (Get-Date).AddDays(-30); " +
                "  $logons = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$s} -MaxEvents 3000 -ErrorAction SilentlyContinue | ForEach-Object { $h = Datos $_; " +
                "    if (($h['LogonType'] -eq '10') -or ($h['LogonType'] -eq '3' -and $h['IpAddress'] -and $h['IpAddress'] -notin '-','::1','127.0.0.1')) { " +
                "      [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); User = $h['TargetUserName']; Ip = $h['IpAddress']; Type = $h['LogonType'] } } }); " +
                "  $failed = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$s} -MaxEvents 3000 -ErrorAction SilentlyContinue | ForEach-Object { $h = Datos $_; " +
                "    [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); User = $h['TargetUserName']; Ip = $h['IpAddress'] } }); " +
                "  $users = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720;StartTime=$s30} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { $h = Datos $_; " +
                "    [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); User = $h['TargetUserName'] } }); " +
                "  $admins = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732;StartTime=$s30} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { $h = Datos $_; " +
                "    if ($h['TargetSid'] -eq 'S-1-5-32-544') { [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); User = $h['MemberSid'] } } }); " +
                "  $cleared = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=$s30} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('o') } }); " +
                "  $cleared += @(Get-WinEvent -FilterHashtable @{LogName='System';Id=104;StartTime=$s30} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('o') } }) " +
                "}; " +
                "ConvertTo-Json -InputObject @{ ok = $ok; logons = $logons; failed = $failed; users = $users; admins = $admins; cleared = $cleared } -Depth 4 -Compress";

            ParseEvents(CommandRunner.PowerShell(script, 180000), d);

            ctx.SubProgress?.Invoke("Intrusión: configuración de seguridad");
            ParseExclusions(CommandRunner.PowerShell(
                "$p = Get-MpPreference -ErrorAction SilentlyContinue; " +
                "ConvertTo-Json -InputObject @{ paths = @($p.ExclusionPath); processes = @($p.ExclusionProcess); extensions = @($p.ExclusionExtension) } -Compress", 30000), d);

            try
            {
                string hosts = System.IO.Path.Combine(d.Paths.SystemRoot, "System32", "drivers", "etc", "hosts");

                if (File.Exists(hosts))
                {
                    d.HostsLines = File.ReadAllLines(hosts).ToList();
                }
            }
            catch (Exception)
            {
            }

            try
            {
                using RegistryKey? k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                bool activo = k?.GetValue("ProxyEnable") is int pe && pe == 1;
                d.ProxyServer = activo ? k?.GetValue("ProxyServer")?.ToString() ?? "" : "";
                d.AutoConfigUrl = k?.GetValue("AutoConfigURL")?.ToString() ?? "";
            }
            catch (Exception)
            {
            }

            string servicios = CommandRunner.PowerShell(
                "$r = Get-Service WinRM,sshd -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object Name; ConvertTo-Json -InputObject @($r) -Compress", 20000);

            try
            {
                using JsonDocument doc = JsonDocument.Parse(servicios.Trim() == "" ? "[]" : servicios);
                foreach (JsonElement e in doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray() : Enumerable.Empty<JsonElement>())
                {
                    string nombre = Str(e, "Name");

                    if (nombre != "")
                    {
                        d.RemoteServices.Add(nombre);
                    }
                }
            }
            catch (JsonException)
            {
            }

            return d;
        }
    }
}
