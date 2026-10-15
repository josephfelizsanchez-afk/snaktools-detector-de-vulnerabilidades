using System.Diagnostics;
using System.Net;

namespace snaktools
{
    internal static class ActionsMenu
    {
        public static void Show(VulnerabilityScanner scanner)
        {
            bool volver = false;

            while (!volver)
            {
                Console.WriteLine();
                Console.WriteLine("Medidas disponibles:");
                Console.WriteLine("1. Actualizar el sistema operativo");
                Console.WriteLine("2. Revisar el firewall");
                Console.WriteLine("3. Revisar o desinstalar programas instalados");
                Console.WriteLine("4. Abrir el panel del router (para cambiar la contraseña de la red)");
                Console.WriteLine("5. Marcar los dispositivos actuales de la red como confiables");
                Console.WriteLine("6. Abrir la configuración del WiFi");
                Console.WriteLine("7. Volver al menú");
                Console.Write("Opción: ");

                switch ((Console.ReadLine() ?? "").Trim())
                {
                    case "1":
                        UpdateSystem();
                        break;
                    case "2":
                        ReviewFirewall();
                        break;
                    case "3":
                        ReviewPrograms();
                        break;
                    case "4":
                        OpenRouter(scanner);
                        break;
                    case "5":
                        TrustDevices(scanner);
                        break;
                    case "6":
                        OpenWifiSettings();
                        break;
                    case "7":
                        volver = true;
                        break;
                    default:
                        Console.WriteLine("Opción inválida.");
                        break;
                }
            }
        }

        private static void UpdateSystem()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("ms-settings:windowsupdate");
            }
            else if (OperatingSystem.IsLinux())
            {
                Console.WriteLine("Ejecuta en una terminal: sudo apt update && sudo apt upgrade (o el gestor de tu distribución).");
            }
            else
            {
                Console.WriteLine("Ve a Ajustes del Sistema > General > Actualización de software.");
            }
        }

        private static void ReviewFirewall()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("firewall.cpl");
            }
            else if (OperatingSystem.IsLinux())
            {
                Console.WriteLine("Ejecuta en una terminal: sudo ufw enable");
            }
            else
            {
                Console.WriteLine("Ve a Ajustes del Sistema > Red > Firewall.");
            }
        }

        private static void ReviewPrograms()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("appwiz.cpl");
            }
            else
            {
                Console.WriteLine("Usa el gestor de paquetes de tu sistema para actualizar o quitar el software riesgoso.");
            }
        }

        private static void OpenRouter(VulnerabilityScanner scanner)
        {
            IPAddress? puerta = scanner.Gateway ?? NetworkChecks.GetNetworkInfo().Gateway;

            if (puerta == null)
            {
                Console.WriteLine("No se encontró el router. Revisa tu conexión de red.");
            }
            else
            {
                Console.WriteLine($"Abriendo http://{puerta} ... Inicia sesión y cambia la contraseña del WiFi y la del panel de administración.");
                OpenTarget($"http://{puerta}");
            }
        }

        private static void TrustDevices(VulnerabilityScanner scanner)
        {
            if (scanner.LastDevices.Count == 0)
            {
                Console.WriteLine("Primero haz un escaneo de red para tener la lista de dispositivos.");
            }
            else
            {
                NetworkChecks.SaveTrusted(scanner.LastDevices);
                Console.WriteLine($"Se marcaron {scanner.LastDevices.Count} dispositivos como confiables.");
            }
        }

        private static void OpenWifiSettings()
        {
            if (OperatingSystem.IsWindows())
            {
                OpenTarget("ms-settings:network-wifi");
            }
            else
            {
                Console.WriteLine("Abre la configuración de red de tu sistema para revisar la seguridad del WiFi.");
            }
        }

        // Abre un archivo, carpeta, enlace o configuración con el programa predeterminado del sistema.
        public static void OpenTarget(string destino)
        {
            try
            {
                Process.Start(new ProcessStartInfo(destino) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"No se pudo abrir '{destino}': {ex.Message}");
            }
        }
    }
}