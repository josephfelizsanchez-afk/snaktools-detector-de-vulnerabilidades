# snaktools

Programa de seguridad para Windows hecho en C#. Revisa tu equipo y tu red en busca de vulnerabilidades, virus e intrusiones, te muestra lo que encontró y tú decides qué hacer. Funciona desde la terminal y guarda todo en un reporte (texto y HTML).

> **Versión 2.0.** Es un proyecto personal y de aprendizaje. No reemplaza a un antivirus completo: úsalo como una capa extra de revisión.

## Qué puede hacer

**Vulnerabilidades**
- Revisa el equipo: firewall, Defender, SMBv1, escritorio remoto, UAC, cuenta de invitado, parches, puertos abiertos y seguridad del WiFi.
- Consulta la base de datos de vulnerabilidades del NIST (CVE) para los programas instalados.
- Escanea los dispositivos de tu red local y avisa de los que no reconoce.

**Virus y malware**
- Usa un escaneo rápido de Microsoft Defender y lee lo que encuentra.
- Compara la huella (hash) de los archivos con una lista de malware conocido y, si pones una API key, con VirusTotal (solo se envía el hash, nunca el archivo).
- Reglas propias: archivos en carpetas temporales, doble extensión (`factura.pdf.exe`), programas que se hacen pasar por procesos de Windows, formas raras de iniciarse solos, comandos de PowerShell ocultos o codificados, mineros de criptomonedas, etc.
- Distingue un virus de un programa normal: revisa la firma digital, la ubicación y el comportamiento. Los programas firmados por fabricantes conocidos no se marcan.
- Cada hallazgo se clasifica como *confirmado*, *probablemente malicioso* o *sospechoso*. Un "sospechoso" no significa virus.

**Intrusiones y acceso remoto**
- Conexiones activas desde internet (Escritorio remoto, VNC, SSH...), intentos de adivinar contraseñas, cuentas nuevas o nuevos administradores, registros de eventos borrados, exclusiones raras de Defender, archivo hosts modificado, proxy y herramientas de acceso remoto abiertas.
- Estima un nivel de riesgo y propone acciones inmediatas: bloquear la IP del intruso, cerrar un proceso, desactivar el Escritorio remoto o quitar una exclusión de Defender. Todas se pueden deshacer.
- Sugiere medidas preventivas según lo que encontró.

**Limpieza segura**
- Nada se elimina sin tu confirmación. Antes de actuar ves el nombre, la ruta y qué hace cada elemento, y eliges uno por uno o todos los confirmados.
- Lo que apartas va a una **cuarentena** de la que se puede restaurar. También se quitan sus formas de inicio (con copia de seguridad).
- Nunca toca archivos de la carpeta de Windows, programas firmados por fabricantes conocidos ni tus documentos.

**IA opcional (apagada por defecto)**
- Puede pedir una segunda opinión a uno o varios analistas: un modelo local con Ollama, Claude, o cualquier servicio compatible con OpenAI.
- La IA solo opina: nunca decide ni elimina nada. Si los analistas no coinciden, el reporte dice que lo revises tú. Puede equivocarse.
- Solo recibe datos del hallazgo (nombre, firma, señales), nunca el contenido de tus archivos. Los servicios en internet están bloqueados hasta que actives `PermitirNube`.

**Otros**
- Escaneo automático opcional (diario o semanal), con prioridad baja y solo cuando el equipo está sin uso. No elimina nada solo: al terminar te avisa y, al hacer clic en la notificación, abre el reporte.
- Aviso de versiones nuevas con los botones "Actualizar ahora" y "Más tarde". La descarga se verifica con SHA-256.
- Reportes con fecha, comparación con el escaneo anterior, lo que hizo el programa y las medidas recomendadas.

## Descarga

1. Entra a la sección [Releases](https://github.com/josephfelizsanchez-afk/snaktools-detector-de-vulnerabilidades/releases).
2. Descarga `snaktools-vX.Y.Z-win-x64.zip` y descomprímelo en una carpeta tuya (Escritorio o Documentos).
3. Abre `snaktools.exe`. No necesitas instalar .NET. Para resultados completos, déjalo reiniciarse como administrador.

Windows SmartScreen puede avisar porque el programa no está firmado digitalmente: *Más información > Ejecutar de todas formas*. El código completo está en este repositorio.

## Menú

| Opción | Qué hace |
|---|---|
| 1 | Vulnerabilidades del equipo |
| 2 | Vulnerabilidades de la red |
| 3 | Buscar virus y malware |
| 4 | Detectar intrusiones y acceso remoto |
| 5 | Escaneo de seguridad total |
| 6 | Cuarentena y bloqueos (ver, restaurar, deshacer) |
| 7 | Programar un escaneo automático (opcional) |
| 8 / 9 | Abrir el último reporte / la carpeta de reportes |
| 10 | Buscar actualizaciones |

## Configuración

La primera vez que lo abres se crea `config.json` junto al ejecutable. Algunas opciones:

```json
{
  "NvdApiKey": "",
  "Malware": { "VirusTotalApiKey": "" },
  "Intrusion": { "ContencionAutomatica": false },
  "Ia": {
    "Activa": false,
    "PermitirNube": false,
    "Analistas": [ { "Nombre": "Local (Ollama)", "Tipo": "ollama", "Modelo": "llama3.1:8b", "Activo": true } ]
  },
  "Actualizaciones": { "Buscar": true }
}
```

- **NvdApiKey** (gratis en nvd.nist.gov) hace mucho más rápida la consulta de CVE.
- **VirusTotalApiKey** activa la consulta de hashes en VirusTotal. También sirven las variables de entorno `NVD_API_KEY` y `VIRUSTOTAL_API_KEY`.
- **Lista propia de malware:** pon hashes SHA-256 (uno por línea) en `hashes_malware.txt`.
- **ContencionAutomatica:** si la activas, bloquea sola la IP de una conexión remota activa desde internet. Viene apagada.
- No subas tu `config.json` a ningún sitio: puede tener claves.

## Cómo probarlo sin riesgo

No hace falta descargar virus. Crea un archivo cualquiera dentro de una carpeta temporal, calcula su hash con `Get-FileHash` y ponlo en `hashes_malware.txt`: el programa lo tratará como amenaza confirmada y podrás probar la cuarentena y la restauración. También detecta el archivo de prueba estándar EICAR (aunque Windows Defender lo borra en cuanto se crea).

## Límites

- La búsqueda de virus, intrusiones y WiFi funciona en Windows. En Linux y macOS solo hay revisiones básicas del sistema.
- No detecta todo el malware existente ni tiene protección en tiempo real. Para eso usa Microsoft Defender u otro antivirus.
- Los hallazgos de intrusión son señales, no pruebas: una herramienta de acceso remoto o un inicio de sesión pueden ser tuyos.
- La consulta de CVE solo cubre una lista de programas conocidos (se pueden agregar más en `config.json`).

## Compilar desde el código

Necesitas el SDK de .NET (10 o superior):

```bash
git clone https://github.com/josephfelizsanchez-afk/snaktools-detector-de-vulnerabilidades
cd snaktools-detector-de-vulnerabilidades
dotnet run
```

Los reportes, la cuarentena y el `config.json` se guardan junto al ejecutable.

## Uso responsable

Usa el escaneo de red solo en redes que sean tuyas o en las que tengas permiso. Escanear dispositivos ajenos sin autorización puede ser ilegal.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE).