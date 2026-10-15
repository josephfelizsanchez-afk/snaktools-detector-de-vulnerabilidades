namespace snaktools
{
    enum ScanType
    {
        Equipo,        // vulnerabilidades del equipo
        Red,           // vulnerabilidades de la red
        Completo,      // equipo + red
        Malware,       // virus y malware
        Intrusion,     // intrusión y acceso remoto
        Total,         // todo lo anterior
        TotalSinRed    // todo menos el escaneo de red (el que usa el escaneo programado)
    }
}
