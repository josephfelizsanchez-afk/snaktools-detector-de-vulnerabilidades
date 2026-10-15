using System.Text.Json;

namespace snaktools
{
    // Resultados guardados para no volver a consultar al NIST cada vez.
    class CveCacheEntry
    {
        public DateTime Date { get; set; }
        public List<CveInfo> Cves { get; set; } = new List<CveInfo>();
    }

    class CveCache
    {
        public Dictionary<string, CveCacheEntry> Entries { get; set; } = new Dictionary<string, CveCacheEntry>();

        public static CveCache Load()
        {
            try
            {
                if (File.Exists(AppPaths.CveCacheFile))
                {
                    CveCache? cache = JsonSerializer.Deserialize<CveCache>(File.ReadAllText(AppPaths.CveCacheFile));

                    if (cache != null)
                    {
                        return cache;
                    }
                }
            }
            catch (Exception)
            {
                // Si el archivo está dañado se empieza de cero.
            }

            return new CveCache();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(AppPaths.ReportsDir);
                File.WriteAllText(AppPaths.CveCacheFile, JsonSerializer.Serialize(this));
            }
            catch (Exception)
            {
                // Sin caché las próximas consultas serán más lentas, nada más.
            }
        }

        public List<CveInfo>? Get(string clave, int horas)
        {
            if (Entries.TryGetValue(clave, out CveCacheEntry? entrada) && (DateTime.UtcNow - entrada.Date).TotalHours < horas)
            {
                return entrada.Cves;
            }

            return null;
        }

        public void Set(string clave, List<CveInfo> cves)
        {
            Entries[clave] = new CveCacheEntry { Date = DateTime.UtcNow, Cves = cves };
        }
    }

    // Busca vulnerabilidades conocidas (CVE) de los programas instalados en la base de datos del NIST.
    internal static class CveChecks
    {
        // Programas conocidos y cómo se llaman en la base del NIST. Se pueden agregar más en config.json.
        private static readonly CpeMapping[] Conocidos =
        {
            new CpeMapping { Contiene = "Google Chrome",       Vendor = "google",               Producto = "chrome" },
            new CpeMapping { Contiene = "Mozilla Firefox",     Vendor = "mozilla",              Producto = "firefox" },
            new CpeMapping { Contiene = "Mozilla Thunderbird", Vendor = "mozilla",              Producto = "thunderbird" },
            new CpeMapping { Contiene = "Microsoft Edge",      Vendor = "microsoft",            Producto = "edge_chromium", Excluye = "WebView" },
            new CpeMapping { Contiene = "7-Zip",               Vendor = "7-zip",                Producto = "7-zip" },
            new CpeMapping { Contiene = "WinRAR",              Vendor = "rarlab",               Producto = "winrar" },
            new CpeMapping { Contiene = "VLC media player",    Vendor = "videolan",             Producto = "vlc_media_player" },
            new CpeMapping { Contiene = "Notepad++",           Vendor = "notepad-plus-plus",    Producto = @"notepad\+\+" },
            new CpeMapping { Contiene = "FileZilla",           Vendor = "filezilla-project",    Producto = "filezilla_client" },
            new CpeMapping { Contiene = "WinSCP",              Vendor = "winscp",               Producto = "winscp" },
            new CpeMapping { Contiene = "PuTTY",               Vendor = "putty",                Producto = "putty" },
            new CpeMapping { Contiene = "=Git",                Vendor = "git-scm",              Producto = "git" },
            new CpeMapping { Contiene = "=Node.js",            Vendor = "nodejs",               Producto = "node.js" },
            new CpeMapping { Contiene = "Wireshark",           Vendor = "wireshark",            Producto = "wireshark" },
            new CpeMapping { Contiene = "VirtualBox",          Vendor = "oracle",               Producto = "vm_virtualbox" },
            new CpeMapping { Contiene = "Docker Desktop",      Vendor = "docker",               Producto = "desktop" },
            new CpeMapping { Contiene = "Visual Studio Code",  Vendor = "microsoft",            Producto = "visual_studio_code", Excluye = "Insiders" },
            new CpeMapping { Contiene = "GIMP",                Vendor = "gimp",                 Producto = "gimp" },
            new CpeMapping { Contiene = "OBS Studio",          Vendor = "obsproject",           Producto = "obs_studio" },
            new CpeMapping { Contiene = "qBittorrent",         Vendor = "qbittorrent",          Producto = "qbittorrent" },
            new CpeMapping { Contiene = "Audacity",            Vendor = "audacityteam",         Producto = "audacity" },
            new CpeMapping { Contiene = "Telegram Desktop",    Vendor = "telegram",             Producto = "telegram_desktop" },
            new CpeMapping { Contiene = "TeamViewer",          Vendor = "teamviewer",           Producto = "teamviewer" },
            new CpeMapping { Contiene = "AnyDesk",             Vendor = "anydesk",              Producto = "anydesk" },
            new CpeMapping { Contiene = "Inkscape",            Vendor = "inkscape",             Producto = "inkscape" },
            new CpeMapping { Contiene = "Blender",             Vendor = "blender",              Producto = "blender" },
            new CpeMapping { Contiene = "LibreOffice",         Vendor = "libreoffice",          Producto = "libreoffice" }
        };

        public static void Run(ScanContext ctx)
        {
            AppConfig cfg = ctx.Config;

            if (!SoftwareChecks.LoadPrograms(ctx))
            {
                return;
            }

            // Programas instalados que están en la lista de productos conocidos
            var candidatos = new List<(string Nombre, string Version, CpeMapping Cpe)>();
            var vistos = new HashSet<string>();

            foreach ((string nombre, string version) in ctx.Programs)
            {
                CpeMapping? cpe = FindMapping(cfg, nombre);

                if (cpe != null && version != "" && vistos.Add($"{cpe.Vendor}:{cpe.Producto}:{version}"))
                {
                    candidatos.Add((nombre, version, cpe));
                }
            }

            if (candidatos.Count == 0)
            {
                ctx.Notes.Add("CVE: ningún programa instalado coincide con la lista de programas conocidos (puedes agregar más en config.json, sección ProgramasCpe).");
                return;
            }

            int maximo = Math.Max(1, cfg.MaxProgramasCve);
            int omitidos = Math.Max(0, candidatos.Count - maximo);
            candidatos = candidatos.Take(maximo).ToList();

            CveCache cache = CveCache.Load();
            var cliente = new NvdClient(cfg);
            int consultados = 0;
            int conCve = 0;
            int rechazados = 0;
            bool abortar = false;

            for (int i = 0; i < candidatos.Count && !abortar; i++)
            {
                var c = candidatos[i];
                ctx.SubProgress?.Invoke($"CVE {i + 1}/{candidatos.Count}: {Corto(c.Nombre)}");

                string clave = $"{c.Cpe.Vendor}:{c.Cpe.Producto}:{c.Version}";

                try
                {
                    List<CveInfo>? cves = cache.Get(clave, cfg.CacheCveHoras);

                    if (cves == null)
                    {
                        cves = cliente.FindCves(c.Cpe.Vendor, c.Cpe.Producto, c.Version);

                        if (cves != null)
                        {
                            cache.Set(clave, cves);
                        }
                    }

                    if (cves == null)
                    {
                        rechazados++;
                    }
                    else
                    {
                        consultados++;

                        if (cves.Count > 0)
                        {
                            conCve++;
                            AddFinding(ctx, c.Nombre, c.Version, cves);
                        }
                    }
                }
                catch (NvdUnavailableException ex)
                {
                    ctx.Notes.Add("CVE: " + ex.Message);
                    abortar = true;
                }
            }

            cache.Save();

            string resumen = $"CVE: se consultaron {consultados} de {candidatos.Count} programas conocidos en la base del NIST (NVD); {conCve} con vulnerabilidades conocidas.";

            if (rechazados > 0)
            {
                resumen += $" No se pudo consultar: {rechazados}.";
            }

            if (omitidos > 0)
            {
                resumen += $" Quedaron {omitidos} sin consultar por el límite de MaxProgramasCve en config.json.";
            }

            ctx.Notes.Add(resumen);

            if (cliente.RequestCount > 0 && !cliente.HasApiKey)
            {
                ctx.Notes.Add("CVE: sin API key del NIST cada consulta espera unos 6 segundos. Puedes pedir una gratis en nvd.nist.gov/developers/request-an-api-key y ponerla en config.json (NvdApiKey).");
            }
        }

        private static void AddFinding(ScanContext ctx, string nombre, string version, List<CveInfo> cves)
        {
            List<CveInfo> ordenadas = cves.OrderByDescending(c => c.Exploited).ThenByDescending(c => c.Score).ToList();
            CveInfo peor = ordenadas[0];
            bool explotada = cves.Any(c => c.Exploited);

            int nivel = Severity.Bajo;

            if (peor.Score >= 7.0 || explotada)
            {
                nivel = Severity.Alto;
            }
            else if (peor.Score >= 4.0)
            {
                nivel = Severity.Medio;
            }

            string masGraves = string.Join(", ", ordenadas.Take(3).Select(c => $"{c.Id} ({c.Score:0.0})"));
            string descripcion = cves.Count == 1
                ? $"1 vulnerabilidad conocida (CVE) afecta a la versión {version}: {masGraves}."
                : $"{cves.Count} vulnerabilidades conocidas (CVE) afectan a la versión {version}. Más graves: {masGraves}.";

            if (explotada)
            {
                descripcion += " Al menos una está siendo explotada activamente (catálogo KEV de CISA).";
            }

            descripcion += " Actualiza el programa a la última versión y verifica los detalles en nvd.nist.gov.";

            ctx.Add($"CVE conocidos en {nombre}", descripcion, nivel);
        }

        private static CpeMapping? FindMapping(AppConfig cfg, string nombre)
        {
            foreach (CpeMapping m in cfg.ProgramasCpe.Concat(Conocidos))
            {
                if (Matches(m, nombre))
                {
                    return m;
                }
            }

            return null;
        }

        private static bool Matches(CpeMapping m, string nombre)
        {
            if (m.Contiene == "" || m.Vendor == "" || m.Producto == "")
            {
                return false;
            }

            if (m.Excluye != "" && nombre.Contains(m.Excluye, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (m.Contiene.StartsWith("="))
            {
                return nombre.Equals(m.Contiene.Substring(1), StringComparison.OrdinalIgnoreCase);
            }

            return nombre.Contains(m.Contiene, StringComparison.OrdinalIgnoreCase);
        }

        private static string Corto(string texto)
        {
            return texto.Length > 32 ? texto.Substring(0, 32) : texto;
        }
    }
}
