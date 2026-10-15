namespace snaktools
{
    // Sugerencias automáticas para que no vuelva a pasar, según lo que se encontró.
    internal static class Recommendations
    {
        public static List<string> Build(ScanContext ctx)
        {
            var urgentes = new List<string>();
            var normales = new List<string>();
            var tags = new HashSet<string>(ctx.Intrusion.Select(h => h.Tag));
            bool hayAmenazaReal = ctx.Threats.Any(t => t.Verdict >= ThreatVerdict.Probable);
            bool intrusionSeria = ctx.IntrusionRisk == "Alto" || tags.Contains("sesion-remota-activa") || tags.Contains("acceso-tras-fuerza-bruta");

            if (intrusionSeria)
            {
                urgentes.Add("Si sospechas que alguien tiene acceso ahora mismo, desconecta el equipo de internet (cable o WiFi) hasta terminar la limpieza.");
                urgentes.Add("Desde OTRO dispositivo que no esté afectado (tu celular, por ejemplo), cambia las contraseñas de tu correo, bancos y redes sociales, y activa la verificación en dos pasos. No lo hagas desde este equipo.");
            }

            if (hayAmenazaReal)
            {
                urgentes.Add("Pon en cuarentena las amenazas confirmadas y después vuelve a escanear para comprobar que no queden restos ni formas de inicio.");
                urgentes.Add("Si el virus llevaba tiempo en el equipo, cambia también las contraseñas guardadas en los navegadores.");
            }

            if (tags.Contains("sesion-remota-activa") || tags.Contains("rdp-publico") || tags.Contains("fuerza-bruta") || tags.Contains("acceso-tras-fuerza-bruta"))
            {
                normales.Add("Desactiva el Escritorio remoto si no lo usas (o permítelo solo con VPN) y no expongas el puerto 3389 a internet.");
                normales.Add("Usa contraseñas largas y únicas (mínimo 14 caracteres) y activa el bloqueo de cuenta tras varios intentos fallidos.");
            }

            if (tags.Contains("usuario-nuevo") || tags.Contains("admin-nuevo"))
            {
                normales.Add("Revisa en Configuración > Cuentas las cuentas del equipo y elimina las que no reconozcas. Usa una cuenta estándar (sin administrador) para el uso diario.");
            }

            if (tags.Contains("exclusion-defender"))
            {
                normales.Add("Revisa en Seguridad de Windows > Protección contra virus > Exclusiones que solo estén las que tú agregaste.");
            }

            if (tags.Contains("herramienta-remota"))
            {
                normales.Add("Desinstala las herramientas de acceso remoto que no uses y, en las que sí uses, activa la contraseña y la verificación en dos pasos.");
            }

            if (tags.Contains("hosts") || tags.Contains("proxy"))
            {
                normales.Add("Restaura el archivo hosts a su contenido original y desactiva el proxy si no lo configuraste tú.");
            }

            if (tags.Contains("logs-borrados"))
            {
                normales.Add("Como se borraron registros de eventos, asume que pueden faltar pruebas: conviene una revisión más profunda, o reinstalar Windows si el compromiso se confirma (guarda antes tus archivos personales sin ejecutar programas).");
            }

            if (ctx.Found.Any(v => v.Name.Contains("CVE conocidos")))
            {
                normales.Add("Actualiza los programas que tienen vulnerabilidades conocidas (CVE) a su última versión.");
            }

            normales.Add("Mantén Windows y Microsoft Defender actualizados, y deja el firewall activado.");
            normales.Add("No abras archivos adjuntos ni descargues programas de fuentes que no conozcas; desconfía de archivos con doble extensión (factura.pdf.exe).");
            normales.Add("Haz copias de seguridad de tus archivos importantes en un disco o nube desconectados del equipo.");
            normales.Add("Revisa las extensiones de tu navegador y desinstala las que no uses.");

            var lista = new List<string>();
            lista.AddRange(urgentes.Select(u => "URGENTE: " + u));
            lista.AddRange(normales);
            return lista;
        }
    }
}
