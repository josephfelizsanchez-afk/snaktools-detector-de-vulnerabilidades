using System.Text.Json;

namespace snaktools
{
    // Lectura y escritura sencilla de archivos JSON.
    internal static class JsonStore
    {
        private static readonly JsonSerializerOptions Options = new JsonSerializerOptions { WriteIndented = true };

        public static T Load<T>(string path) where T : new()
        {
            try
            {
                if (File.Exists(path))
                {
                    T? valor = JsonSerializer.Deserialize<T>(File.ReadAllText(path));

                    if (valor != null)
                    {
                        return valor;
                    }
                }
            }
            catch (Exception)
            {
            }

            return new T();
        }

        public static bool Save<T>(string path, T valor)
        {
            try
            {
                string? carpeta = Path.GetDirectoryName(path);

                if (!string.IsNullOrEmpty(carpeta))
                {
                    Directory.CreateDirectory(carpeta);
                }

                File.WriteAllText(path, JsonSerializer.Serialize(valor, Options));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    // Lo que el programa recuerda entre ejecuciones.
    class AppState
    {
        public DateTime LastUpdateCheckUtc { get; set; } = DateTime.MinValue;
        public DateTime SnoozeUpdateUntilUtc { get; set; } = DateTime.MinValue;
        public List<string> TrustedHashes { get; set; } = new List<string>();          // archivos que el usuario marcó como confiables
        public List<ThreatCandidate> PendingThreats { get; set; } = new List<ThreatCandidate>();   // amenazas del último escaneo programado
        public DateTime LastScheduledRunUtc { get; set; } = DateTime.MinValue;
    }

    internal static class StateStore
    {
        private static readonly object Candado = new object();

        public static AppState Load()
        {
            lock (Candado)
            {
                return JsonStore.Load<AppState>(AppPaths.StateFile);
            }
        }

        public static void Save(AppState estado)
        {
            lock (Candado)
            {
                JsonStore.Save(AppPaths.StateFile, estado);
            }
        }

        public static bool IsTrusted(string sha256)
        {
            return sha256 != "" && Load().TrustedHashes.Contains(sha256, StringComparer.OrdinalIgnoreCase);
        }

        public static void Trust(string sha256)
        {
            if (sha256 == "")
            {
                return;
            }

            AppState estado = Load();

            if (!estado.TrustedHashes.Contains(sha256, StringComparer.OrdinalIgnoreCase))
            {
                estado.TrustedHashes.Add(sha256);
                Save(estado);
            }
        }
    }
}
