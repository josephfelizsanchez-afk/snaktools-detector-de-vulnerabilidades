using System.Text;

namespace snaktools
{
    // Reporte en texto plano (.txt)
    internal static class ReportGenerator
    {
        public static string Save(Report r, string path)
        {
            var sb = new StringBuilder();
            string admin = r.IsAdministrator ? "Sí" : "No";
            string gravedadMax = r.HighestSeverity == 0 ? "Ninguna" : Severity.Name(r.HighestSeverity);

            sb.AppendLine("REPORTE DE VULNERABILIDADES - snaktools");
            sb.AppendLine("=======================================");
            sb.AppendLine($"Fecha y hora del escaneo: {r.ScanDate:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"Tipo de escaneo: {r.KindName}");
            sb.AppendLine($"Duración: {r.DurationSeconds} s");
            sb.AppendLine($"Sistema: {r.SystemInfo}");
            sb.AppendLine($"Permisos de administrador: {admin}");
            sb.AppendLine($"Vulnerabilidades encontradas: {r.TotalVulnerabilities}");
            sb.AppendLine($"Gravedad más alta: {gravedadMax}");

            if (r.IntrusionRisk != "")
            {
                sb.AppendLine($"Riesgo estimado de intrusión: {r.IntrusionRisk}");
            }

            if (r.Threats.Count > 0)
            {
                sb.AppendLine($"Amenazas de virus o malware: {r.Threats.Count}");
            }
            sb.AppendLine($"Puntaje de riesgo (suma de gravedades): {r.TotalSeverityLevel}");
            sb.AppendLine($"Escaneos en esta sesión: {r.SessionScans} ({r.SessionVulnerabilities} vulnerabilidades en total, {r.SessionDuration} s, gravedad acumulada {r.SessionSeverity})");

            if (r.InstalledPrograms > 0)
            {
                sb.AppendLine($"Programas instalados revisados: {r.InstalledPrograms}");
            }

            sb.AppendLine();

            if (r.HasPreviousScan)
            {
                sb.AppendLine("=== Cambios desde el escaneo anterior ===");
                sb.AppendLine($"Nuevas: {r.NewVulnerabilities.Count}   Resueltas: {r.ResolvedVulnerabilities.Count}");

                foreach (string nueva in r.NewVulnerabilities)
                {
                    sb.AppendLine($"+ NUEVA: {nueva}");
                }

                foreach (string resuelta in r.ResolvedVulnerabilities)
                {
                    sb.AppendLine($"- RESUELTA: {resuelta}");
                }

                sb.AppendLine();
            }

            if (r.Vulnerabilities.Count == 0)
            {
                sb.AppendLine("No se encontraron vulnerabilidades con las revisiones actuales.");
                sb.AppendLine();
            }
            else
            {
                foreach (var grupo in r.Vulnerabilities.GroupBy(v => v.SeverityLevel).OrderByDescending(g => g.Key))
                {
                    sb.AppendLine($"=== Gravedad {Severity.Name(grupo.Key)} ({grupo.Count()}) ===");

                    foreach (Vulnerability v in grupo)
                    {
                        sb.AppendLine($"- {v.Name}");
                        sb.AppendLine($"  {v.Description}");
                    }

                    sb.AppendLine();
                }
            }

            if (r.Threats.Count > 0)
            {
                sb.AppendLine("=== Virus y malware encontrados ===");

                foreach (ThreatCandidate t in r.Threats)
                {
                    sb.AppendLine($"- [{t.VerdictText}] {t.Name}");
                    sb.AppendLine($"  Ruta: {t.Path}");

                    if (t.Sha256 != "")
                    {
                        sb.AppendLine($"  SHA-256: {t.Sha256}");
                    }

                    sb.AppendLine($"  Detectado por: {t.Source} (puntaje {t.Score}/100)");
                    sb.AppendLine($"  Qué hace: {t.WhatItDoes}");

                    foreach (string razon in t.Reasons)
                    {
                        sb.AppendLine($"  - {razon}");
                    }

                    foreach (string nota in t.AiNotes)
                    {
                        sb.AppendLine($"  IA (no verificada): {nota}");
                    }
                }

                sb.AppendLine();
            }

            if (r.Intrusion.Count > 0)
            {
                sb.AppendLine($"=== Posible intrusión o acceso remoto (riesgo: {r.IntrusionRisk}) ===");

                foreach (IntrusionFinding h in r.Intrusion)
                {
                    sb.AppendLine($"- [{Severity.Name(h.Severity)}, confianza {h.Confidence.ToLowerInvariant()}] {h.Title}");
                    sb.AppendLine($"  {h.Description}");

                    foreach (string ev in h.Evidence)
                    {
                        sb.AppendLine($"  Evidencia: {ev}");
                    }
                }

                sb.AppendLine();
            }

            if (r.Actions.Count > 0)
            {
                sb.AppendLine("=== Lo que hizo snaktools ===");

                foreach (ActionRecord a in r.Actions)
                {
                    sb.AppendLine($"- {a.Time:HH:mm:ss} {(a.Success ? "OK" : "NO SE PUDO")}: {a.Action} - {a.Target}. {a.Detail}");
                }

                sb.AppendLine();
            }
            else if (r.Threats.Count > 0 || r.Intrusion.Count > 0)
            {
                sb.AppendLine("snaktools no hizo ningún cambio en el equipo.");
                sb.AppendLine();
            }

            if (r.Recommendations.Count > 0)
            {
                sb.AppendLine("=== Medidas preventivas recomendadas ===");

                for (int i = 0; i < r.Recommendations.Count; i++)
                {
                    sb.AppendLine($"{i + 1}. {r.Recommendations[i]}");
                }

                sb.AppendLine();
            }

            if (r.AiNotes.Count > 0)
            {
                sb.AppendLine("=== Opinión de la IA (no verificada; puede equivocarse) ===");

                foreach (string nota in r.AiNotes)
                {
                    sb.AppendLine($"- {nota}");
                }

                sb.AppendLine();
            }

            if (r.Devices.Count > 0)
            {
                sb.AppendLine("=== Dispositivos activos en la red ===");

                foreach (NetworkDevice d in r.Devices)
                {
                    string etiqueta = d.Ip == r.GatewayIp ? " (router)" : "";
                    string mac = string.IsNullOrEmpty(d.Mac) ? "no disponible" : d.Mac;
                    sb.AppendLine($"- {d.Ip}{etiqueta}  MAC: {mac}");
                }

                sb.AppendLine();
            }

            if (r.Notes.Count > 0)
            {
                sb.AppendLine("=== Notas ===");

                foreach (string nota in r.Notes)
                {
                    sb.AppendLine($"- {nota}");
                }
            }

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            return Path.GetFullPath(path);
        }
    }
}
