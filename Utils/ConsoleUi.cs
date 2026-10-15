namespace snaktools
{
    internal static class ConsoleUi
    {
        public static void Write(string text, ConsoleColor color)
        {
            ConsoleColor anterior = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ForegroundColor = anterior;
        }

        public static void WriteLine(string text, ConsoleColor color)
        {
            Write(text, color);
            Console.WriteLine();
        }

        public static ConsoleColor SeverityColor(int level)
        {
            switch (level)
            {
                case Severity.Alto:
                    return ConsoleColor.Red;
                case Severity.Medio:
                    return ConsoleColor.Yellow;
                case Severity.Bajo:
                    return ConsoleColor.Cyan;
                default:
                    return ConsoleColor.Gray;
            }
        }

        // Barra de progreso en una sola línea: [#####---------------] 1/4 Texto
        public static void Progress(int actual, int total, string texto)
        {
            const int ancho = 20;
            int llenos = total == 0 ? ancho : (int)Math.Round((double)actual / total * ancho);
            llenos = Math.Clamp(llenos, 0, ancho);

            string barra = new string('#', llenos) + new string('-', ancho - llenos);
            string linea = $"[{barra}] {actual}/{total} {texto}";

            if (linea.Length > 79)
            {
                linea = linea.Substring(0, 79);
            }

            ConsoleColor anterior = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\r" + linea.PadRight(79));
            Console.ForegroundColor = anterior;

            if (actual >= total)
            {
                Console.WriteLine();
            }
        }

        public static bool AskYesNo(string pregunta)
        {
            bool respondio = false;
            bool resultado = false;

            while (!respondio)
            {
                Console.Write($"{pregunta} (s/n): ");
                string respuesta = (Console.ReadLine() ?? "n").Trim().ToLower();   // si se cierra la entrada, se toma como "no"

                if (respuesta == "s" || respuesta == "si" || respuesta == "sí")
                {
                    resultado = true;
                    respondio = true;
                }
                else if (respuesta == "n" || respuesta == "no")
                {
                    respondio = true;
                }
                else
                {
                    Console.WriteLine("Responda 's' o 'n'.");
                }
            }

            return resultado;
        }

        public static void Pause(string mensaje = "Presione Enter para continuar...")
        {
            Console.Write(mensaje);
            Console.ReadLine();
        }
    }
}
