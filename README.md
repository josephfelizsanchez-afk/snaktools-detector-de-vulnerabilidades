# snaktools

Programa de consola en C# que revisa tu equipo y tu red local en busca de vulnerabilidades y guarda los resultados en un reporte de texto, con su nivel de gravedad (bajo, medio o alto).

> **Estado:** versión 1.0 en desarrollo. Lo que está listo funciona, pero todavía faltan cosas (ver "Lo que viene").

## Qué puede hacer ahora

**Escaneo del equipo**
- En Windows revisa: firewall, Microsoft Defender (protección en tiempo real y definiciones), SMBv1, escritorio remoto, UAC, cuenta de invitado y si hay parches recientes.
- En Linux y macOS hace revisiones más básicas (SSH con root, firewall, actualizaciones pendientes, SIP y FileVault).
- Detecta puertos abiertos y accesibles desde la red que suelen ser riesgosos (Telnet, SMB, RDP, VNC, bases de datos, etc.).
- En Windows revisa los programas instalados contra una lista corta de software obsoleto o con vulnerabilidades conocidas.

**Escaneo de la red**
- Encuentra los dispositivos de tu subred (por ping) y prueba algunos puertos riesgosos en cada uno.
- Guarda una lista de dispositivos confiables y avisa cuando aparece uno nuevo.

**Reporte, notificación y medidas**
- Guarda todo en `reporte_vulnerabilidades.txt` con fecha, hora, duración y vulnerabilidades ordenadas por gravedad.
- Muestra una notificación del sistema cuando termina el escaneo.
- Ofrece acciones rápidas: abrir Windows Update, el firewall, la lista de programas o el panel del router para cambiar la contraseña del WiFi.

## Requisitos

- .NET 8 o superior
- Para obtener resultados completos, ejecútalo como administrador (o root)

## Cómo usarlo

```bash
git clone https://github.com/josephfelizsanchez-afk/snaktools-detector-de-vulnerabilidades
cd snaktools-detector-de-vulnerabilidades
dotnet run
```

Elige una opción del menú: escanear el equipo, escanear la red o salir.

## Limitaciones actuales

- La revisión de programas instalados solo funciona en Windows y no consulta la base de datos de CVE, solo usa una lista corta.
- Las revisiones de Linux y macOS son básicas y están menos probadas.
- El escaneo corre en segundo plano mientras muestra el progreso, pero no es un servicio que se ejecute solo.
- El escaneo de red asume una subred /24 y solo encuentra dispositivos que respondan a ping.

## Lo que viene

- Interfaz gráfica (ventana) para no depender de la terminal
- Consulta de vulnerabilidades reales con la API de NVD (CVE)
- Más revisiones para Linux y macOS
- Ejecución programada en segundo plano

## Uso responsable

Usa el escaneo de red solo en redes que sean tuyas o en las que tengas permiso. Escanear dispositivos ajenos sin autorización puede ser ilegal.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
