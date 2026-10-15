using System.Net;
using System.Text;

namespace snaktools
{
    // Reporte en HTML con colores por gravedad
    internal static class HtmlReportGenerator
    {
        private const string Css = """
            :root { color-scheme: dark; }
            body { margin: 0; background: #0b1220; color: #e6edf7; font-family: Segoe UI, Arial, sans-serif; line-height: 1.5; }
            main { max-width: 900px; margin: 0 auto; padding: 32px 20px; }
            h1 { margin: 0 0 4px; font-size: 26px; }
            h2 { margin-top: 32px; font-size: 18px; border-bottom: 1px solid #1f2a44; padding-bottom: 6px; }
            .meta { color: #8fa3c4; font-size: 14px; }
            .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 20px; }
            .card { background: #111a2e; border: 1px solid #1f2a44; border-radius: 10px; padding: 14px; text-align: center; }
            .card .num { display: block; font-size: 30px; font-weight: 700; }
            .num.sev3 { color: #e5484d; }
            .num.sev2 { color: #f5a524; }
            .num.sev1 { color: #3b9cf5; }
            .vuln { background: #111a2e; border: 1px solid #1f2a44; border-left: 5px solid #888; border-radius: 8px; padding: 10px 14px; margin: 10px 0; }
            .vuln p { margin: 4px 0 0; color: #b8c5de; font-size: 14px; }
            .vuln.sev3 { border-left-color: #e5484d; }
            .vuln.sev2 { border-left-color: #f5a524; }
            .vuln.sev1 { border-left-color: #3b9cf5; }
            table { width: 100%; border-collapse: collapse; font-size: 14px; }
            th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #1f2a44; }
            .ok { color: #3ecf8e; }
            .urgent { color: #ff8a8a; font-weight: 600; }
            .risk-Alto { color: #e5484d; }
            .risk-Medio { color: #f5a524; }
            .risk-Bajo { color: #3b9cf5; }
            .small { font-size: 13px; color: #8fa3c4; }
            .ia { background: #14213d; border: 1px dashed #2c4170; border-radius: 8px; padding: 8px 12px; margin: 8px 0; font-size: 13px; color: #b8c5de; }
            .bad { color: #e5484d; }
            ul { padding-left: 20px; color: #b8c5de; font-size: 14px; }
            footer { margin-top: 40px; color: #6b7c9c; font-size: 12px; }
            """;

        private static string E(string texto)
        {
            return WebUtility.HtmlEncode(texto);
        }

        public static string Save(Report r, string path)
        {
            var sb = new StringBuilder();
            int altas = r.Vulnerabilities.Count(v => v.SeverityLevel == Severity.Alto);
            int medias = r.Vulnerabilities.Count(v => v.SeverityLevel == Severity.Medio);
            int bajas = r.Vulnerabilities.Count(v => v.SeverityLevel == Severity.Bajo);
            string admin = r.IsAdministrator ? "Sí" : "No";

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"es\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.AppendLine("<title>Reporte snaktools</title>");
            sb.AppendLine("<style>");
            sb.AppendLine(Css);
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body><main>");

            sb.AppendLine("<h1>snaktools · Reporte de vulnerabilidades</h1>");
            sb.AppendLine($"<div class=\"meta\">{r.ScanDate:dd/MM/yyyy HH:mm:ss} · Escaneo: {E(r.KindName)} · {r.DurationSeconds} s · Administrador: {admin}</div>");
            sb.AppendLine($"<div class=\"meta\">{E(r.SystemInfo)}</div>");

            sb.AppendLine("<div class=\"cards\">");
            sb.AppendLine($"<div class=\"card\"><span class=\"num\">{r.TotalVulnerabilities}</span>Total</div>");
            sb.AppendLine($"<div class=\"card\"><span class=\"num sev3\">{altas}</span>Alto</div>");
            sb.AppendLine($"<div class=\"card\"><span class=\"num sev2\">{medias}</span>Medio</div>");
            sb.AppendLine($"<div class=\"card\"><span class=\"num sev1\">{bajas}</span>Bajo</div>");

            if (r.Threats.Count > 0)
            {
                sb.AppendLine($"<div class=\"card\"><span class=\"num sev3\">{r.Threats.Count}</span>Amenazas</div>");
            }

            if (r.IntrusionRisk != "")
            {
                string claseRiesgo = r.IntrusionRisk.StartsWith("Alto") ? "risk-Alto" : r.IntrusionRisk.StartsWith("Medio") ? "risk-Medio" : "risk-Bajo";
                sb.AppendLine($"<div class=\"card\"><span class=\"num {claseRiesgo}\" style=\"font-size:20px\">{E(r.IntrusionRisk)}</span>Riesgo de intrusión</div>");
            }

            sb.AppendLine("</div>");

            if (r.HasPreviousScan)
            {
                sb.AppendLine("<h2>Cambios desde el escaneo anterior</h2>");

                if (r.NewVulnerabilities.Count == 0 && r.ResolvedVulnerabilities.Count == 0)
                {
                    sb.AppendLine("<p class=\"meta\">Sin cambios.</p>");
                }
                else
                {
                    sb.AppendLine("<ul>");

                    foreach (string nueva in r.NewVulnerabilities)
                    {
                        sb.AppendLine($"<li class=\"bad\">Nueva: {E(nueva)}</li>");
                    }

                    foreach (string resuelta in r.ResolvedVulnerabilities)
                    {
                        sb.AppendLine($"<li class=\"ok\">Resuelta: {E(resuelta)}</li>");
                    }

                    sb.AppendLine("</ul>");
                }
            }

            if (r.Vulnerabilities.Count == 0)
            {
                sb.AppendLine("<h2>Resultado</h2>");
                sb.AppendLine("<p class=\"ok\">No se encontraron vulnerabilidades con las revisiones actuales.</p>");
            }
            else
            {
                foreach (var grupo in r.Vulnerabilities.GroupBy(v => v.SeverityLevel).OrderByDescending(g => g.Key))
                {
                    sb.AppendLine($"<h2>Gravedad {E(Severity.Name(grupo.Key))} ({grupo.Count()})</h2>");

                    foreach (Vulnerability v in grupo)
                    {
                        sb.AppendLine($"<div class=\"vuln sev{v.SeverityLevel}\"><strong>{E(v.Name)}</strong><p>{E(v.Description)}</p></div>");
                    }
                }
            }

            if (r.Threats.Count > 0)
            {
                sb.AppendLine("<h2>Virus y malware encontrados</h2>");

                foreach (ThreatCandidate t in r.Threats)
                {
                    int nivel = t.Verdict == ThreatVerdict.Sospechoso ? 2 : 3;
                    sb.AppendLine($"<div class=\"vuln sev{nivel}\"><strong>{E(t.VerdictText)}: {E(t.Name)}</strong>");
                    sb.AppendLine($"<p>Ruta: {E(t.Path)}</p>");
                    sb.AppendLine($"<p>Qué hace: {E(t.WhatItDoes)}</p>");
                    sb.AppendLine($"<p class=\"small\">Detectado por: {E(t.Source)} · puntaje {t.Score}/100" + (t.Sha256 != "" ? $" · SHA-256: {E(t.Sha256)}" : "") + "</p>");

                    foreach (string razon in t.Reasons)
                    {
                        sb.AppendLine($"<p class=\"small\">• {E(razon)}</p>");
                    }

                    foreach (string nota in t.AiNotes)
                    {
                        sb.AppendLine($"<div class=\"ia\">IA (no verificada): {E(nota)}</div>");
                    }

                    sb.AppendLine("</div>");
                }
            }

            if (r.Intrusion.Count > 0)
            {
                sb.AppendLine($"<h2>Posible intrusión o acceso remoto (riesgo: {E(r.IntrusionRisk)})</h2>");

                foreach (IntrusionFinding h in r.Intrusion)
                {
                    sb.AppendLine($"<div class=\"vuln sev{h.Severity}\"><strong>{E(h.Title)}</strong><p>{E(h.Description)}</p>");
                    sb.AppendLine($"<p class=\"small\">Gravedad {E(Severity.Name(h.Severity))} · confianza {E(h.Confidence.ToLowerInvariant())}</p>");

                    foreach (string ev in h.Evidence)
                    {
                        sb.AppendLine($"<p class=\"small\">Evidencia: {E(ev)}</p>");
                    }

                    sb.AppendLine("</div>");
                }
            }

            sb.AppendLine("<h2>Lo que hizo snaktools</h2>");

            if (r.Actions.Count == 0)
            {
                sb.AppendLine("<p class=\"ok\">No se hizo ningún cambio en el equipo.</p>");
            }
            else
            {
                sb.AppendLine("<ul>");

                foreach (ActionRecord a in r.Actions)
                {
                    string clase = a.Success ? "ok" : "bad";
                    sb.AppendLine($"<li class=\"{clase}\">{a.Time:HH:mm:ss} · {E(a.Action)} · {E(a.Target)}. {E(a.Detail)}</li>");
                }

                sb.AppendLine("</ul>");
            }

            if (r.Recommendations.Count > 0)
            {
                sb.AppendLine("<h2>Medidas preventivas recomendadas</h2>");
                sb.AppendLine("<ol>");

                foreach (string recomendacion in r.Recommendations)
                {
                    string clase = recomendacion.StartsWith("URGENTE") ? " class=\"urgent\"" : "";
                    sb.AppendLine($"<li{clase}>{E(recomendacion)}</li>");
                }

                sb.AppendLine("</ol>");
            }

            if (r.AiNotes.Count > 0)
            {
                sb.AppendLine("<h2>Opinión de la IA (no verificada)</h2>");
                sb.AppendLine("<p class=\"small\">La IA solo da una opinión y puede equivocarse. No cambia ningún veredicto ni elimina nada.</p>");

                foreach (string nota in r.AiNotes)
                {
                    sb.AppendLine($"<div class=\"ia\">{E(nota)}</div>");
                }
            }

            if (r.Devices.Count > 0)
            {
                sb.AppendLine("<h2>Dispositivos activos en la red</h2>");
                sb.AppendLine("<table><tr><th>IP</th><th>MAC</th><th></th></tr>");

                foreach (NetworkDevice d in r.Devices)
                {
                    string etiqueta = d.Ip == r.GatewayIp ? "Router" : "";
                    string mac = string.IsNullOrEmpty(d.Mac) ? "no disponible" : d.Mac;
                    sb.AppendLine($"<tr><td>{E(d.Ip)}</td><td>{E(mac)}</td><td>{etiqueta}</td></tr>");
                }

                sb.AppendLine("</table>");
            }

            if (r.Notes.Count > 0)
            {
                sb.AppendLine("<h2>Notas</h2>");
                sb.AppendLine("<ul>");

                foreach (string nota in r.Notes)
                {
                    sb.AppendLine($"<li>{E(nota)}</li>");
                }

                sb.AppendLine("</ul>");
            }

            sb.AppendLine("<footer>Generado por snaktools</footer>");
            sb.AppendLine("</main></body></html>");

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            return Path.GetFullPath(path);
        }
    }
}
