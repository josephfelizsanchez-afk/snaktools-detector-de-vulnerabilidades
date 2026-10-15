using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace snaktools
{
    class ReleaseInfo
    {
        public string Version { get; set; } = "";
        public string Notes { get; set; } = "";
        public string PageUrl { get; set; } = "";
        public string AssetName { get; set; } = "";
        public string AssetUrl { get; set; } = "";
        public string Sha256 { get; set; } = "";
    }

    // Avisa cuando hay una versión nueva y la instala si el usuario lo acepta.
    internal static class UpdateService
    {
        // Solo se descarga de los sitios permitidos (GitHub por defecto), siempre con https.
        public static bool IsAllowedUrl(string url, UpdateConfig cfg)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? u) || u.Scheme != Uri.UriSchemeHttps)
            {
                return false;
            }

            string host = u.Host.ToLowerInvariant();
            return cfg.HostsPermitidos.Any(h => h != "" && (host == h.ToLowerInvariant() || host.EndsWith("." + h.ToLowerInvariant())));
        }

        public static bool IsNewer(string nueva, string actual)
        {
            return VersionUtil.Compare(nueva.TrimStart('v', 'V'), actual.TrimStart('v', 'V')) > 0;
        }

        public static ReleaseInfo? ParseRelease(string json)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement r = doc.RootElement;

                string Texto(JsonElement e, string n) => e.TryGetProperty(n, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

                string version = Texto(r, "tag_name").TrimStart('v', 'V');

                if (version == "")
                {
                    return null;
                }

                var info = new ReleaseInfo { Version = version, Notes = Texto(r, "body"), PageUrl = Texto(r, "html_url") };

                if (r.TryGetProperty("assets", out JsonElement assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    var zips = assets.EnumerateArray().Where(a => Texto(a, "name").EndsWith(".zip", StringComparison.OrdinalIgnoreCase)).ToList();
                    JsonElement? elegido = zips.Cast<JsonElement?>().FirstOrDefault(a => Texto(a!.Value, "name").Contains("win-x64", StringComparison.OrdinalIgnoreCase))
                                           ?? zips.Cast<JsonElement?>().FirstOrDefault();

                    if (elegido != null)
                    {
                        info.AssetName = Texto(elegido.Value, "name");
                        info.AssetUrl = Texto(elegido.Value, "browser_download_url");
                        string digest = Texto(elegido.Value, "digest");

                        if (digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                        {
                            info.Sha256 = digest.Substring(7).Trim().ToLowerInvariant();
                        }
                    }
                }

                if (info.Sha256 == "")
                {
                    Match m = Regex.Match(info.Notes, @"(?i)sha-?256\s*[:=]?\s*`?([0-9a-f]{64})");

                    if (m.Success)
                    {
                        info.Sha256 = m.Groups[1].Value.ToLowerInvariant();
                    }
                }

                return info;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        public static ReleaseInfo? FetchLatest(UpdateConfig cfg)
        {
            try
            {
                if (!IsAllowedUrl(cfg.Url, cfg) && !cfg.Url.StartsWith("http://127.0.0.1") && !cfg.Url.StartsWith("http://localhost"))
                {
                    return null;
                }

                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("snaktools/" + AppInfo.Version);
                http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

                using var peticion = new HttpRequestMessage(HttpMethod.Get, cfg.Url);
                using HttpResponseMessage respuesta = http.Send(peticion);

                if (!respuesta.IsSuccessStatusCode)
                {
                    return null;
                }

                using var lector = new StreamReader(respuesta.Content.ReadAsStream());
                return ParseRelease(lector.ReadToEnd());
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Al abrir el programa: busca una versión nueva como máximo una vez cada cierto tiempo.
        public static void CheckOnStartup(AppConfig cfg)
        {
            if (!cfg.Actualizaciones.Buscar)
            {
                return;
            }

            AppState estado = StateStore.Load();

            if (DateTime.UtcNow < estado.SnoozeUpdateUntilUtc
                || (DateTime.UtcNow - estado.LastUpdateCheckUtc).TotalHours < Math.Max(1, cfg.Actualizaciones.HorasEntreBusquedas))
            {
                return;
            }

            ReleaseInfo? ultima = FetchLatest(cfg.Actualizaciones);
            estado.LastUpdateCheckUtc = DateTime.UtcNow;
            StateStore.Save(estado);

            if (ultima != null && IsNewer(ultima.Version, AppInfo.Version))
            {
                Offer(cfg, ultima, estado);
            }
        }

        // Desde el menú: busca ahora mismo.
        public static void CheckNow(AppConfig cfg)
        {
            Console.WriteLine("Buscando actualizaciones...");
            ReleaseInfo? ultima = FetchLatest(cfg.Actualizaciones);

            if (ultima == null)
            {
                Console.WriteLine("No se pudo consultar la última versión (sin internet, o el repositorio de GitHub es privado).");
                return;
            }

            AppState estado = StateStore.Load();
            estado.LastUpdateCheckUtc = DateTime.UtcNow;
            StateStore.Save(estado);

            if (IsNewer(ultima.Version, AppInfo.Version))
            {
                Offer(cfg, ultima, estado);
            }
            else
            {
                ConsoleUi.WriteLine($"Ya tienes la última versión ({AppInfo.Version}).", ConsoleColor.Green);
            }
        }

        private static void Offer(AppConfig cfg, ReleaseInfo r, AppState estado)
        {
            string notas = r.Notes.Length > 500 ? r.Notes.Substring(0, 500) + "..." : r.Notes;

            if (Dialogs.AskUpdate(r.Version, notas.Replace("\r", "")))
            {
                Apply(cfg, r);
            }
            else
            {
                estado.SnoozeUpdateUntilUtc = DateTime.UtcNow.AddHours(24);
                StateStore.Save(estado);
                Console.WriteLine("Está bien, te lo recordaré más tarde (también puedes actualizar desde el menú).");
            }
        }

        // Descarga, verifica e instala la versión nueva.
        public static void Apply(AppConfig cfg, ReleaseInfo r)
        {
            string? exeActual = Environment.ProcessPath;

            if (exeActual == null || Path.GetFileNameWithoutExtension(exeActual).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Estás ejecutando snaktools desde el código (dotnet run); no se puede actualizar solo.");
                Console.WriteLine("Descarga la versión nueva aquí: " + r.PageUrl);
                return;
            }

            if (r.AssetUrl == "")
            {
                Console.WriteLine("La versión nueva no tiene un archivo .zip para descargar. Entra aquí: " + r.PageUrl);
                return;
            }

            if (!Download(cfg.Actualizaciones, r, out string nuevoExe, out string error))
            {
                ConsoleUi.WriteLine("No se pudo descargar la actualización: " + error, ConsoleColor.Red);
                Console.WriteLine("Puedes descargarla a mano: " + r.PageUrl);
                return;
            }

            if (r.Sha256 == "")
            {
                ConsoleUi.WriteLine("Aviso: esta versión no publica su huella SHA-256, así que no se pudo verificar la descarga.", ConsoleColor.Yellow);

                if (!ConsoleUi.AskYesNo("¿Instalarla de todos modos?"))
                {
                    try { File.Delete(nuevoExe); } catch (Exception) { }
                    return;
                }
            }

            string scriptRuta = Path.Combine(Path.GetTempPath(), "snaktools_actualizar_" + Guid.NewGuid().ToString("N") + ".ps1");
            File.WriteAllText(scriptRuta, BuildUpdaterScript(), new UTF8Encoding(false));

            var psi = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
            foreach (string a in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptRuta,
                                         "-ProcessId", Environment.ProcessId.ToString(), "-Source", nuevoExe, "-Target", exeActual })
            {
                psi.ArgumentList.Add(a);
            }

            Process.Start(psi);
            Console.WriteLine("Actualizando snaktools... el programa se cerrará y se volverá a abrir solo.");
            Environment.Exit(0);
        }

        // Descarga el .zip (validando cada redirección), comprueba el SHA-256 y extrae el ejecutable.
        public static bool Download(UpdateConfig cfg, ReleaseInfo r, out string exeRuta, out string error)
        {
            exeRuta = "";
            error = "";
            string carpeta = Path.Combine(Path.GetTempPath(), "snaktools_update_" + Guid.NewGuid().ToString("N"));

            try
            {
                if (!IsAllowedUrl(r.AssetUrl, cfg) && !r.AssetUrl.StartsWith("http://127.0.0.1"))
                {
                    error = "La dirección de descarga no es de un sitio permitido.";
                    return false;
                }

                Directory.CreateDirectory(carpeta);
                string zipRuta = Path.Combine(carpeta, "update.zip");

                using var manejador = new HttpClientHandler { AllowAutoRedirect = false };
                using var http = new HttpClient(manejador) { Timeout = TimeSpan.FromMinutes(10) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("snaktools/" + AppInfo.Version);

                string url = r.AssetUrl;

                for (int salto = 0; salto < 6; salto++)
                {
                    using var peticion = new HttpRequestMessage(HttpMethod.Get, url);
                    using HttpResponseMessage resp = http.Send(peticion, HttpCompletionOption.ResponseHeadersRead);
                    int codigo = (int)resp.StatusCode;

                    if (codigo >= 300 && codigo < 400 && resp.Headers.Location != null)
                    {
                        string siguiente = new Uri(new Uri(url), resp.Headers.Location).ToString();

                        if (!IsAllowedUrl(siguiente, cfg) && !siguiente.StartsWith("http://127.0.0.1"))
                        {
                            error = "La descarga intentó redirigir a un sitio no permitido.";
                            return false;
                        }

                        url = siguiente;
                        continue;
                    }

                    if (!resp.IsSuccessStatusCode)
                    {
                        error = $"el servidor respondió con el error {codigo}";
                        return false;
                    }

                    if (resp.Content.Headers.ContentLength > 300L * 1024 * 1024)
                    {
                        error = "el archivo es demasiado grande";
                        return false;
                    }

                    using (Stream entrada = resp.Content.ReadAsStream())
                    using (FileStream salida = File.Create(zipRuta))
                    {
                        entrada.CopyTo(salida);
                    }

                    break;
                }

                if (!File.Exists(zipRuta))
                {
                    error = "demasiadas redirecciones";
                    return false;
                }

                if (r.Sha256 != "")
                {
                    string hash;
                    using (FileStream fs = File.OpenRead(zipRuta))
                    {
                        hash = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
                    }

                    if (hash != r.Sha256.ToLowerInvariant())
                    {
                        error = "la huella SHA-256 no coincide (descarga dañada o alterada); se canceló.";
                        File.Delete(zipRuta);
                        return false;
                    }
                }

                using (ZipArchive zip = ZipFile.OpenRead(zipRuta))
                {
                    ZipArchiveEntry? entrada = zip.Entries.FirstOrDefault(e => e.Name.Equals("snaktools.exe", StringComparison.OrdinalIgnoreCase));

                    if (entrada == null)
                    {
                        error = "el .zip no contiene snaktools.exe";
                        return false;
                    }

                    exeRuta = Path.Combine(carpeta, "snaktools.exe");
                    entrada.ExtractToFile(exeRuta, true);
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        // Script que espera a que snaktools se cierre, reemplaza el .exe (guardando una copia .old) y lo vuelve a abrir.
        public static string BuildUpdaterScript()
        {
            return string.Join("\r\n", new[]
            {
                "param([int]$ProcessId, [string]$Source, [string]$Target)",
                "try { Wait-Process -Id $ProcessId -Timeout 90 -ErrorAction SilentlyContinue } catch { }",
                "Start-Sleep -Seconds 1",
                "try {",
                "  if (Test-Path -LiteralPath $Target) { Copy-Item -LiteralPath $Target -Destination ($Target + '.old') -Force }",
                "  Copy-Item -LiteralPath $Source -Destination $Target -Force",
                "  Start-Process -FilePath $Target",
                "} catch {",
                "  Add-Type -AssemblyName PresentationFramework",
                "  [System.Windows.MessageBox]::Show('No se pudo actualizar snaktools: ' + $_.Exception.Message, 'snaktools')",
                "}",
                "Remove-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue",
                ""
            });
        }
    }
}
