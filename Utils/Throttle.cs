namespace snaktools
{
    // Frena el programa para no saturar el equipo (modo de bajo consumo).
    internal static class Throttle
    {
        public static bool Enabled { get; set; } = false;
        public static int SleepMs { get; set; } = 25;

        public static void Tick()
        {
            if (Enabled && SleepMs > 0)
            {
                Thread.Sleep(SleepMs);
            }
        }
    }
}
