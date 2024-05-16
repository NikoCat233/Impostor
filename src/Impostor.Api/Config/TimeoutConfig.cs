namespace Impostor.Api.Config
{
    public class TimeoutConfig
    {
        public const string Section = "Timeout";

        public int SpawnTimeout { get; set; } = 3000;

        public int ConnectionTimeout { get; set; } = 2500;
    }
}
