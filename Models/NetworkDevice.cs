namespace snaktools
{
    class NetworkDevice
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";

        // Identificador para la lista de confiables: la MAC si se conoce, si no la IP.
        public string Id => string.IsNullOrEmpty(Mac) ? Ip : Mac;
    }
}