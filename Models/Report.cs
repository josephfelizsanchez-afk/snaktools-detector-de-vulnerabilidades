namespace snaktools
{
    class Report
    {
        public DateTime ScanDate { get; set; }
        public ScanType Kind { get; set; }
        public int DurationSeconds { get; set; }
        public string SystemInfo { get; set; } = "";
        public bool IsAdministrator { get; set; }
        public int InstalledPrograms { get; set; }
        public string? GatewayIp { get; set; }

        public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public List<NetworkDevice> Devices { get; set; } = new List<NetworkDevice>();
        public List<string> Notes { get; set; } = new List<string>();

        // Virus, intrusión, acciones, sugerencias e IA
        public List<ThreatCandidate> Threats { get; set; } = new List<ThreatCandidate>();
        public List<IntrusionFinding> Intrusion { get; set; } = new List<IntrusionFinding>();
        public string IntrusionRisk { get; set; } = "";
        public List<ActionRecord> Actions { get; set; } = new List<ActionRecord>();
        public List<string> Recommendations { get; set; } = new List<string>();
        public List<string> AiNotes { get; set; } = new List<string>();

        // Comparación con el escaneo anterior del mismo tipo
        public bool HasPreviousScan { get; set; }
        public List<string> NewVulnerabilities { get; set; } = new List<string>();
        public List<string> ResolvedVulnerabilities { get; set; } = new List<string>();

        // Totales de la sesión (desde que se abrió el programa)
        public int SessionScans { get; set; }
        public int SessionVulnerabilities { get; set; }
        public int SessionSeverity { get; set; }
        public int SessionDuration { get; set; }

        public int TotalVulnerabilities => Vulnerabilities.Count;
        public int TotalSeverityLevel => Vulnerabilities.Sum(v => v.SeverityLevel);
        public int HighestSeverity => Vulnerabilities.Count > 0 ? Vulnerabilities.Max(v => v.SeverityLevel) : 0;

        public string KindName
        {
            get
            {
                switch (Kind)
                {
                    case ScanType.Equipo: return "Vulnerabilidades del equipo";
                    case ScanType.Red: return "Red";
                    case ScanType.Completo: return "Equipo y red";
                    case ScanType.Malware: return "Virus y malware";
                    case ScanType.Intrusion: return "Intrusión y acceso remoto";
                    case ScanType.Total: return "Escaneo total (equipo, virus, intrusión y red)";
                    default: return "Escaneo de seguridad (equipo, virus e intrusión)";
                }
            }
        }
    }
}
