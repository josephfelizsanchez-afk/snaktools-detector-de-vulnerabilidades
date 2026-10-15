using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace snaktools
{
    class AiOpinion
    {
        public string Analyst { get; set; } = "";
        public string Verdict { get; set; } = "incierto";    // legitimo, sospechoso, malicioso, incierto
        public double Confidence { get; set; }
        public string Reason { get; set; } = "";
        public string Action { get; set; } = "";
    }

    class AiUnavailableException : Exception
    {
        public AiUnavailableException(string message) : base(message) { }
    }

    // Habla con un analista de IA: un modelo local (Ollama), Claude, o cualquier servicio compatible con OpenAI.
    class AiClient
    {
        private readonly AiProviderConfig proveedor;
        private readonly HttpClient http;

        public string Name => proveedor.Nombre != "" ? proveedor.Nombre : proveedor.Tipo;
        public bool IsLocal => Uri.TryCreate(proveedor.Url, UriKind.Absolute, out Uri? u) && (u.IsLoopback || u.Host == "localhost");

        public AiClient(AiProviderConfig proveedor, int timeoutSegundos)
        {
            this.proveedor = proveedor;
            http = new HttpClient { Timeout = TimeSpan.FromSeconds(Math.Max(5, timeoutSegundos)) };
        }

        private string GetKey()
        {
            if (!string.IsNullOrWhiteSpace(proveedor.ApiKey))
            {
                return proveedor.ApiKey.Trim();
            }

            return proveedor.ApiKeyEnv != "" ? (Environment.GetEnvironmentVariable(proveedor.ApiKeyEnv) ?? "").Trim() : "";
        }

        public bool IsConfigured(out string motivo)
        {
            motivo = "";

            if (proveedor.Url == "" || proveedor.Modelo == "")
            {
                motivo = "falta la URL o el modelo";
                return false;
            }

            if (proveedor.Tipo != "ollama" && GetKey() == "")
            {
                motivo = "falta la API key";
                return false;
            }

            return true;
        }

        // Devuelve el texto de la respuesta del modelo.
        public string Ask(string sistema, string usuario)
        {
            string tipo = proveedor.Tipo.ToLowerInvariant();
            string cuerpo;

            using var peticion = new HttpRequestMessage(HttpMethod.Post, proveedor.Url);

            if (tipo == "anthropic")
            {
                cuerpo = JsonSerializer.Serialize(new
                {
                    model = proveedor.Modelo,
                    max_tokens = 600,
                    temperature = 0,
                    system = sistema,
                    messages = new[] { new { role = "user", content = usuario } }
                });
                peticion.Headers.Add("x-api-key", GetKey());
                peticion.Headers.Add("anthropic-version", "2023-06-01");
            }
            else if (tipo == "openai")
            {
                cuerpo = JsonSerializer.Serialize(new
                {
                    model = proveedor.Modelo,
                    temperature = 0,
                    messages = new object[]
                    {
                        new { role = "system", content = sistema },
                        new { role = "user", content = usuario }
                    }
                });
                peticion.Headers.Authorization = new AuthenticationHeaderValue("Bearer", GetKey());
            }
            else
            {
                cuerpo = JsonSerializer.Serialize(new
                {
                    model = proveedor.Modelo,
                    stream = false,
                    format = "json",
                    options = new { temperature = 0 },
                    messages = new object[]
                    {
                        new { role = "system", content = sistema },
                        new { role = "user", content = usuario }
                    }
                });
            }

            peticion.Content = new StringContent(cuerpo, Encoding.UTF8, "application/json");

            HttpResponseMessage respuesta;

            try
            {
                respuesta = http.Send(peticion);
            }
            catch (Exception ex)
            {
                throw new AiUnavailableException($"{Name}: no se pudo conectar ({ex.Message})");
            }

            using (respuesta)
            {
                if (!respuesta.IsSuccessStatusCode)
                {
                    throw new AiUnavailableException($"{Name}: el servicio respondió con el error {(int)respuesta.StatusCode}");
                }

                using Stream contenido = respuesta.Content.ReadAsStream();
                using JsonDocument doc = JsonDocument.Parse(contenido);
                JsonElement raiz = doc.RootElement;

                try
                {
                    if (tipo == "anthropic")
                    {
                        return string.Join("", raiz.GetProperty("content").EnumerateArray()
                            .Where(b => b.TryGetProperty("text", out _))
                            .Select(b => b.GetProperty("text").GetString() ?? ""));
                    }

                    if (tipo == "openai")
                    {
                        return raiz.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? "";
                    }

                    return raiz.GetProperty("message").GetProperty("content").GetString() ?? "";
                }
                catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is IndexOutOfRangeException)
                {
                    throw new AiUnavailableException($"{Name}: la respuesta no tiene el formato esperado");
                }
            }
        }

        // Interpreta la respuesta del modelo. Si no es un JSON válido o dice algo fuera de lo permitido, devuelve null.
        public static AiOpinion? ParseOpinion(string analista, string texto)
        {
            Match m = Regex.Match(texto ?? "", @"\{.*\}", RegexOptions.Singleline);

            if (!m.Success)
            {
                return null;
            }

            try
            {
                using JsonDocument doc = JsonDocument.Parse(m.Value);
                JsonElement r = doc.RootElement;

                string veredicto = Normalize(Texto(r, "veredicto"));

                if (veredicto != "legitimo" && veredicto != "sospechoso" && veredicto != "malicioso" && veredicto != "incierto")
                {
                    return null;
                }

                double confianza = 0;

                if (r.TryGetProperty("confianza", out JsonElement c))
                {
                    if (c.ValueKind == JsonValueKind.Number) confianza = c.GetDouble();
                    else if (c.ValueKind == JsonValueKind.String) double.TryParse(c.GetString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out confianza);
                }

                return new AiOpinion
                {
                    Analyst = analista,
                    Verdict = veredicto,
                    Confidence = Math.Clamp(confianza, 0, 1),
                    Reason = Limitar(Texto(r, "razon"), 400),
                    Action = Limitar(Texto(r, "accion"), 200)
                };
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static string Texto(JsonElement e, string nombre)
        {
            return e.ValueKind == JsonValueKind.Object && e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        }

        private static string Normalize(string s)
        {
            string n = s.Trim().ToLowerInvariant().Replace("í", "i").Replace("é", "e").Replace("á", "a").Replace("ó", "o").Replace("ú", "u");
            return n;
        }

        private static string Limitar(string s, int max)
        {
            string limpio = Regex.Replace(s, @"[\u0000-\u001F]", " ").Trim();
            return limpio.Length > max ? limpio.Substring(0, max) + "..." : limpio;
        }
    }
}
