using System.Text.Json;

namespace snaktools
{
    // Lo que se guarda del último escaneo de cada tipo para poder compararlo con el siguiente.
    class ReportSnapshot
    {
        public DateTime Date { get; set; }
        public List<string> Names { get; set; } = new List<string>();
    }

    internal static class ReportHistory
    {
        private static string SnapshotPath(ScanType kind)
        {
            return Path.Combine(AppPaths.ReportsDir, $"ultimo_{kind.ToString().ToLower()}.json");
        }

        // Compara el reporte actual con el escaneo anterior del mismo tipo.
        public static void Compare(Report report)
        {
            try
            {
                string path = SnapshotPath(report.Kind);

                if (!File.Exists(path))
                {
                    report.HasPreviousScan = false;
                    return;
                }

                ReportSnapshot? anterior = JsonSerializer.Deserialize<ReportSnapshot>(File.ReadAllText(path));

                if (anterior == null)
                {
                    return;
                }

                var actuales = new HashSet<string>(report.Vulnerabilities.Select(v => v.Name));
                var previas = new HashSet<string>(anterior.Names);

                report.HasPreviousScan = true;
                report.NewVulnerabilities = actuales.Where(n => !previas.Contains(n)).ToList();
                report.ResolvedVulnerabilities = previas.Where(n => !actuales.Contains(n)).ToList();
            }
            catch (Exception)
            {
                report.HasPreviousScan = false;
            }
        }

        public static void SaveSnapshot(Report report)
        {
            try
            {
                Directory.CreateDirectory(AppPaths.ReportsDir);

                var snapshot = new ReportSnapshot
                {
                    Date = report.ScanDate,
                    Names = report.Vulnerabilities.Select(v => v.Name).ToList()
                };

                var opciones = new JsonSerializerOptions { WriteIndented = true };
                File.WriteAllText(SnapshotPath(report.Kind), JsonSerializer.Serialize(snapshot, opciones));
            }
            catch (Exception)
            {
                // Si no se puede guardar, solo se pierde la comparación del próximo escaneo.
            }
        }

        // Devuelve la ruta del reporte más reciente (.html o .txt), o null si no hay ninguno.
        public static string? GetLatestReport()
        {
            if (!Directory.Exists(AppPaths.ReportsDir))
            {
                return null;
            }

            return new DirectoryInfo(AppPaths.ReportsDir)
                .GetFiles("reporte_*.*")
                .Where(f => f.Extension == ".html" || f.Extension == ".txt")
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
        }
    }
}