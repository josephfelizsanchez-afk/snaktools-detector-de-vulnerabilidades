using System.Text.Json;

namespace snaktools
{
    // Versión del programa (se compara con la última versión publicada en GitHub).
    internal static class AppInfo
    {
        public const string Version = "2.0.0";
    }

    // Rutas donde el programa guarda sus archivos (junto al .exe).
    internal static class AppPaths
    {
        public static string? QuarantineDirOverride { get; set; }   // solo para pruebas

        public static string BaseDir => AppContext.BaseDirectory;
        public static string ReportsDir => Path.Combine(BaseDir, "reportes");
        public static string ConfigFile => Path.Combine(BaseDir, "config.json");
        public static string TrustedFile => Path.Combine(BaseDir, "dispositivos_confiables.txt");
        public static string LatestReportFile => Path.Combine(BaseDir, "reporte_vulnerabilidades.txt");
        public static string CveCacheFile => Path.Combine(ReportsDir, "cache_cve.json");
        public static string VtCacheFile => Path.Combine(ReportsDir, "cache_virustotal.json");
        public static string StateFile => Path.Combine(BaseDir, "estado.json");
        public static string BlocklistFile => Path.Combine(BaseDir, "hashes_malware.txt");
        public static string ContainmentLogFile => Path.Combine(BaseDir, "contencion.json");

        // La cuarentena va en ProgramData (fuera de las carpetas del usuario).
        public static string QuarantineDir => QuarantineDirOverride
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "snaktools", "cuarentena");

        public static string QuarantineManifest => Path.Combine(QuarantineDir, "manifest.json");
    }

    // Le dice al programa qué producto (CPE) corresponde a un programa instalado.
    class CpeMapping
    {
        public string Contiene { get; set; } = "";
        public string Vendor { get; set; } = "";
        public string Producto { get; set; } = "";
        public string Excluye { get; set; } = "";
    }

    class MalwareConfig
    {
        public bool Activo { get; set; } = true;
        public bool UsarDefender { get; set; } = true;            // pedirle a Microsoft Defender un escaneo rápido y leer lo que encuentra
        public int DefenderTimeoutMin { get; set; } = 15;
        public int MaxArchivos { get; set; } = 3000;              // máximo de archivos a revisar por escaneo
        public int MaxTamanoMB { get; set; } = 100;               // archivos más grandes no se calculan
        public string VirusTotalApiKey { get; set; } = "";        // opcional; también sirve la variable VIRUSTOTAL_API_KEY
        public int MaxConsultasVirusTotal { get; set; } = 8;
        public int UmbralSospechoso { get; set; } = 40;
        public int UmbralProbable { get; set; } = 70;
        public int PausaBajoConsumoMs { get; set; } = 25;
        public List<string> PublicadoresConfiables { get; set; } = new List<string>();
        public List<string> CarpetasExtra { get; set; } = new List<string>();
    }

    class IntrusionConfig
    {
        public bool Activo { get; set; } = true;
        public int DiasEventos { get; set; } = 7;
        public int UmbralFallosInicioSesion { get; set; } = 20;
        public bool ContencionAutomatica { get; set; } = false;   // si es true, bloquea sola la IP de una conexión remota activa desde internet
    }

    class AiProviderConfig
    {
        public string Nombre { get; set; } = "";
        public string Tipo { get; set; } = "ollama";     // ollama, openai (compatible) o anthropic
        public string Url { get; set; } = "";
        public string Modelo { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public string ApiKeyEnv { get; set; } = "";      // nombre de una variable de entorno con la clave
        public bool Activo { get; set; } = false;
    }

    class IaConfig
    {
        public bool Activa { get; set; } = false;
        public bool PermitirNube { get; set; } = false;  // sin esto solo se usan modelos locales (Ollama)
        public int MaxElementos { get; set; } = 8;
        public int TimeoutSegundos { get; set; } = 120;
        public List<AiProviderConfig> Analistas { get; set; } = new List<AiProviderConfig>
        {
            new AiProviderConfig { Nombre = "Local (Ollama)", Tipo = "ollama", Url = "http://localhost:11434/api/chat", Modelo = "llama3.1:8b" },
            new AiProviderConfig { Nombre = "Claude", Tipo = "anthropic", Url = "https://api.anthropic.com/v1/messages", Modelo = "claude-sonnet-5-5", ApiKeyEnv = "ANTHROPIC_API_KEY" },
            new AiProviderConfig { Nombre = "OpenAI compatible", Tipo = "openai", Url = "https://api.openai.com/v1/chat/completions", Modelo = "gpt-4o-mini", ApiKeyEnv = "OPENAI_API_KEY" }
        };
    }

    class UpdateConfig
    {
        public bool Buscar { get; set; } = true;
        public string Url { get; set; } = "https://api.github.com/repos/josephfelizsanchez-afk/snaktools-detector-de-vulnerabilidades/releases/latest";
        public int HorasEntreBusquedas { get; set; } = 24;
        public List<string> HostsPermitidos { get; set; } = new List<string>
        {
            "api.github.com", "github.com", "githubusercontent.com"
        };
    }

    // Opciones que se pueden cambiar editando config.json
    class AppConfig
    {
        public bool RevisarSistema { get; set; } = true;
        public bool RevisarProgramas { get; set; } = true;
        public bool RevisarPuertosLocales { get; set; } = true;
        public bool RevisarWifi { get; set; } = true;
        public bool GenerarHtml { get; set; } = true;
        public bool AbrirReporteAlTerminar { get; set; } = true;
        public int[] PuertosRed { get; set; } = new[] { 21, 23, 139, 445, 3389, 5900 };
        public int TimeoutPuertoMs { get; set; } = 700;

        // Consulta de vulnerabilidades conocidas (CVE) en la base de datos del NIST (NVD)
        public bool RevisarCve { get; set; } = true;
        public string NvdApiKey { get; set; } = "";
        public int MaxProgramasCve { get; set; } = 25;
        public int CacheCveHoras { get; set; } = 72;
        public int NvdPausaMs { get; set; } = 0;
        public string NvdUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        public List<CpeMapping> ProgramasCpe { get; set; } = new List<CpeMapping>();

        public MalwareConfig Malware { get; set; } = new MalwareConfig();
        public IntrusionConfig Intrusion { get; set; } = new IntrusionConfig();
        public IaConfig Ia { get; set; } = new IaConfig();
        public UpdateConfig Actualizaciones { get; set; } = new UpdateConfig();

        // La API key puede ir en config.json o en la variable de entorno NVD_API_KEY.
        public string GetApiKey()
        {
            if (!string.IsNullOrWhiteSpace(NvdApiKey))
            {
                return NvdApiKey.Trim();
            }

            return (Environment.GetEnvironmentVariable("NVD_API_KEY") ?? "").Trim();
        }

        public string GetVirusTotalKey()
        {
            if (!string.IsNullOrWhiteSpace(Malware.VirusTotalApiKey))
            {
                return Malware.VirusTotalApiKey.Trim();
            }

            return (Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY") ?? "").Trim();
        }
    }

    internal static class ConfigService
    {
        public static AppConfig Load()
        {
            AppConfig config;

            try
            {
                if (!File.Exists(AppPaths.ConfigFile))
                {
                    config = new AppConfig();
                }
                else
                {
                    var opciones = new JsonSerializerOptions
                    {
                        ReadCommentHandling = JsonCommentHandling.Skip,
                        AllowTrailingCommas = true
                    };

                    config = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(AppPaths.ConfigFile), opciones) ?? new AppConfig();
                }
            }
            catch (Exception)
            {
                // Si el archivo está dañado se usan los valores por defecto y no se toca el archivo.
                return new AppConfig();
            }

            try
            {
                // Se vuelve a guardar para que aparezcan las opciones nuevas que falten.
                Save(config);
            }
            catch (Exception)
            {
            }

            return config;
        }

        public static void Save(AppConfig config)
        {
            var opciones = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(AppPaths.ConfigFile, JsonSerializer.Serialize(config, opciones));
        }
    }
}
