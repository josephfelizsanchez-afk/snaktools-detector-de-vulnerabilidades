using System.Text.Json;
using System.Text.RegularExpressions;

namespace snaktools
{
    // Una vulnerabilidad conocida (CVE) que afecta a un programa.
    class CveInfo
    {
        public string Id { get; set; } = "";
        public double Score { get; set; }                 // puntaje CVSS (0 a 10)
        public string Severity { get; set; } = "";        // LOW, MEDIUM, HIGH, CRITICAL
        public bool Exploited { get; set; }               // está en el catálogo KEV de CISA (explotada activamente)
        public string Description { get; set; } = "";
    }

    // Se lanza cuando no se puede seguir consultando al NIST (sin internet, límite de consultas, error del servidor).
    class NvdUnavailableException : Exception
    {
        public NvdUnavailableException(string message) : base(message) { }
    }

    // Compara versiones como "6.24", "2.43.0" o "1.0-beta".
    internal static class VersionUtil
    {
        public static int Compare(string a, string b)
        {
            List<string> ta = Tokens(a);
            List<string> tb = Tokens(b);
            int n = Math.Max(ta.Count, tb.Count);

            for (int i = 0; i < n; i++)
            {
                string x = i < ta.Count ? ta[i] : "0";
                string y = i < tb.Count ? tb[i] : "0";
                bool xNumero = char.IsDigit(x[0]);
                bool yNumero = char.IsDigit(y[0]);
                int c;

                if (xNumero && yNumero)
                {
                    c = CompareNumbers(x, y);
                }
                else if (!xNumero && !yNumero)
                {
                    c = Math.Sign(string.Compare(x, y, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    // Un número gana a un texto: 1.0 es mayor que 1.0-beta
                    c = xNumero ? 1 : -1;
                }

                if (c != 0)
                {
                    return c;
                }
            }

            return 0;
        }

        private static List<string> Tokens(string version)
        {
            return Regex.Matches(version, @"\d+|[A-Za-z]+").Select(m => m.Value).ToList();
        }

        private static int CompareNumbers(string x, string y)
        {
            x = x.TrimStart('0');
            y = y.TrimStart('0');

            if (x.Length != y.Length)
            {
                return x.Length < y.Length ? -1 : 1;
            }

            return Math.Sign(string.CompareOrdinal(x, y));
        }
    }

    // Cliente de la API 2.0 de la base de datos de vulnerabilidades del NIST (NVD).
    class NvdClient
    {
        private const int MaxPaginas = 3;

        private readonly HttpClient http;
        private readonly AppConfig config;
        private readonly string apiKey;
        private DateTime ultimaConsulta = DateTime.MinValue;

        public int RequestCount { get; private set; }
        public bool HasApiKey => apiKey != "";

        public NvdClient(AppConfig config)
        {
            this.config = config;
            apiKey = config.GetApiKey();

            http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("snaktools/1.2");

            if (apiKey != "")
            {
                http.DefaultRequestHeaders.Add("apiKey", apiKey);
            }
        }

        // Devuelve las CVE que afectan a la versión indicada de un producto.
        // Devuelve null si el NIST no aceptó la consulta (por ejemplo, producto o versión no válidos).
        // Lanza NvdUnavailableException si no se puede consultar (sin internet, límite de consultas...).
        public List<CveInfo>? FindCves(string vendor, string product, string version)
        {
            string prefijo = $"cpe:2.3:a:{vendor}:{product}";
            var encontradas = new Dictionary<string, CveInfo>();
            int inicio = 0;
            int total = int.MaxValue;
            int paginas = 0;

            // Se piden las CVE de versiones iguales o mayores a la instalada (así un programa al día
            // devuelve casi nada) y después se comprueba aquí cada rango de versiones.
            while (inicio < total && paginas < MaxPaginas)
            {
                string url = config.NvdUrl
                    + "?virtualMatchString=" + Uri.EscapeDataString(prefijo)
                    + "&versionStart=" + Uri.EscapeDataString(version)
                    + "&versionStartType=including"
                    + "&noRejected"
                    + "&startIndex=" + inicio;

                using JsonDocument? doc = Get(url);

                if (doc == null)
                {
                    return paginas == 0 ? null : encontradas.Values.ToList();
                }

                JsonElement raiz = doc.RootElement;
                total = raiz.TryGetProperty("totalResults", out JsonElement t) && t.ValueKind == JsonValueKind.Number ? t.GetInt32() : 0;
                int porPagina = raiz.TryGetProperty("resultsPerPage", out JsonElement p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;

                if (raiz.TryGetProperty("vulnerabilities", out JsonElement lista) && lista.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement item in lista.EnumerateArray())
                    {
                        if (item.TryGetProperty("cve", out JsonElement cve) && Affects(cve, vendor, product, version))
                        {
                            CveInfo info = ToInfo(cve);

                            if (info.Id != "")
                            {
                                encontradas[info.Id] = info;
                            }
                        }
                    }
                }

                paginas++;
                inicio += porPagina > 0 ? porPagina : total;
            }

            return encontradas.Values.ToList();
        }

        // ---------------------------------------------------------------
        // HTTP con pausas para respetar el límite del NIST
        // (5 consultas cada 30 s sin API key, 50 con API key)
        // ---------------------------------------------------------------
        private JsonDocument? Get(string url)
        {
            int espera = config.NvdPausaMs > 0 ? config.NvdPausaMs * 3 : 35000;

            for (int intento = 0; intento < 3; intento++)
            {
                EsperarTurno();

                HttpResponseMessage respuesta;

                try
                {
                    using var peticion = new HttpRequestMessage(HttpMethod.Get, url);
                    respuesta = http.Send(peticion);
                }
                catch (Exception ex)
                {
                    throw new NvdUnavailableException("No se pudo conectar con la base de datos del NIST (NVD). Revisa tu conexión a internet. (" + ex.Message + ")");
                }

                ultimaConsulta = DateTime.UtcNow;
                RequestCount++;

                using (respuesta)
                {
                    int codigo = (int)respuesta.StatusCode;

                    if (respuesta.IsSuccessStatusCode)
                    {
                        using Stream contenido = respuesta.Content.ReadAsStream();
                        return JsonDocument.Parse(contenido);
                    }

                    if (codigo == 400 || codigo == 404)
                    {
                        return null;
                    }

                    bool limite = codigo == 403 || codigo == 429 || codigo == 503;

                    if (!limite)
                    {
                        throw new NvdUnavailableException($"El NIST respondió con el error {codigo}. Se omitió la consulta de CVE.");
                    }
                }

                if (intento < 2)
                {
                    Thread.Sleep(espera);
                }
            }

            throw new NvdUnavailableException("El NIST limitó las consultas (demasiadas en poco tiempo). Intenta más tarde o agrega una API key gratuita en config.json (NvdApiKey).");
        }

        private void EsperarTurno()
        {
            int pausa = config.NvdPausaMs > 0 ? config.NvdPausaMs : (apiKey != "" ? 700 : 6500);
            double transcurrido = (DateTime.UtcNow - ultimaConsulta).TotalMilliseconds;

            if (transcurrido < pausa)
            {
                Thread.Sleep((int)(pausa - transcurrido));
            }
        }

        // ---------------------------------------------------------------
        // Lectura de las CVE
        // ---------------------------------------------------------------

        // Comprueba si la versión instalada cae dentro de los rangos afectados por la CVE.
        private static bool Affects(JsonElement cve, string vendor, string product, string version)
        {
            if (!cve.TryGetProperty("configurations", out JsonElement configuraciones) || configuraciones.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            string prefijo = $"cpe:2.3:a:{vendor}:{product}:".ToLower();

            foreach (JsonElement configuracion in configuraciones.EnumerateArray())
            {
                if (configuracion.TryGetProperty("nodes", out JsonElement nodos) && nodos.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement nodo in nodos.EnumerateArray())
                    {
                        if (nodo.TryGetProperty("cpeMatch", out JsonElement coincidencias) && coincidencias.ValueKind == JsonValueKind.Array)
                        {
                            foreach (JsonElement coincidencia in coincidencias.EnumerateArray())
                            {
                                if (MatchAffects(coincidencia, prefijo, version))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static bool MatchAffects(JsonElement coincidencia, string prefijo, string version)
        {
            if (coincidencia.TryGetProperty("vulnerable", out JsonElement vulnerable) && vulnerable.ValueKind == JsonValueKind.False)
            {
                return false;
            }

            string criterio = Str(coincidencia, "criteria");

            if (!criterio.ToLower().StartsWith(prefijo))
            {
                return false;
            }

            string[] partes = criterio.Split(':');
            string versionCriterio = partes.Length > 5 ? partes[5] : "*";

            if (versionCriterio == "-")
            {
                return false;
            }

            if (versionCriterio != "*")
            {
                // Una versión concreta
                return VersionUtil.Compare(version, versionCriterio) == 0;
            }

            // Un rango de versiones
            string desdeIncl = Str(coincidencia, "versionStartIncluding");
            string desdeExcl = Str(coincidencia, "versionStartExcluding");
            string hastaIncl = Str(coincidencia, "versionEndIncluding");
            string hastaExcl = Str(coincidencia, "versionEndExcluding");

            if (desdeIncl != "" && VersionUtil.Compare(version, desdeIncl) < 0) return false;
            if (desdeExcl != "" && VersionUtil.Compare(version, desdeExcl) <= 0) return false;
            if (hastaIncl != "" && VersionUtil.Compare(version, hastaIncl) > 0) return false;
            if (hastaExcl != "" && VersionUtil.Compare(version, hastaExcl) >= 0) return false;

            return true;
        }

        private static CveInfo ToInfo(JsonElement cve)
        {
            var info = new CveInfo { Id = Str(cve, "id") };

            info.Exploited = cve.TryGetProperty("cisaExploitAdd", out _);

            if (cve.TryGetProperty("descriptions", out JsonElement descripciones) && descripciones.ValueKind == JsonValueKind.Array)
            {
                string texto = descripciones.EnumerateArray()
                    .Where(d => Str(d, "lang") == "en")
                    .Select(d => Str(d, "value"))
                    .FirstOrDefault() ?? "";

                info.Description = texto.Length > 200 ? texto.Substring(0, 200) + "..." : texto;
            }

            if (cve.TryGetProperty("metrics", out JsonElement metricas))
            {
                foreach (string clave in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
                {
                    if (info.Score == 0
                        && metricas.TryGetProperty(clave, out JsonElement lista)
                        && lista.ValueKind == JsonValueKind.Array
                        && lista.GetArrayLength() > 0
                        && lista[0].TryGetProperty("cvssData", out JsonElement datos)
                        && datos.TryGetProperty("baseScore", out JsonElement puntaje)
                        && puntaje.ValueKind == JsonValueKind.Number)
                    {
                        info.Score = puntaje.GetDouble();
                    }
                }
            }

            info.Severity = SeverityFromScore(info.Score);
            return info;
        }

        public static string SeverityFromScore(double score)
        {
            if (score >= 9.0) return "CRITICAL";
            if (score >= 7.0) return "HIGH";
            if (score >= 4.0) return "MEDIUM";
            if (score > 0) return "LOW";
            return "";
        }

        private static string Str(JsonElement elemento, string nombre)
        {
            if (elemento.TryGetProperty(nombre, out JsonElement valor) && valor.ValueKind == JsonValueKind.String)
            {
                return valor.GetString() ?? "";
            }

            return "";
        }
    }
}
