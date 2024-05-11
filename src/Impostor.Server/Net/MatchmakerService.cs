using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Config;
using Impostor.Server.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Impostor.Server.Net
{
    internal class MatchmakerService : IHostedService
    {
        private readonly ILogger<MatchmakerService> _logger;
        private readonly ServerConfig _serverConfig;
        public static HttpServerConfig _httpServerConfig;
        private readonly Matchmaker _matchmaker;
        private Timer _timer;
        public static EACFunctions _eacFunctions;

        public MatchmakerService(
            ILogger<MatchmakerService> logger,
            IOptions<ServerConfig> serverConfig,
            IOptions<HttpServerConfig> httpServerConfig,
            Matchmaker matchmaker)
        {
            _logger = logger;
            _serverConfig = serverConfig.Value;
            _httpServerConfig = httpServerConfig.Value;
            _matchmaker = matchmaker;
            _eacFunctions = new EACFunctions();
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(_serverConfig.ResolveListenIp()), _serverConfig.ListenPort);

            await _matchmaker.StartAsync(endpoint);

            _logger.LogInformation(
                "Matchmaker is listening on {0}:{1}, the public server ip is {2}:{3}.",
                endpoint.Address,
                endpoint.Port,
                _serverConfig.ResolvePublicIp(),
                _serverConfig.PublicPort);

            if (_serverConfig.PublicIp == "127.0.0.1")
            {
                // NOTE: If this warning annoys you, set your PublicIp to "localhost"
                _logger.LogError("Your PublicIp is set to the default value of 127.0.0.1.");
                _logger.LogError("To allow people on other devices to connect to your server, change this value to your Public IP address");
                _logger.LogError("For more info on how to do this see https://github.com/Impostor/Impostor/blob/master/docs/Server-configuration.md");
            }

            var runningOutsideContainer = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == null;
            if (_httpServerConfig.ListenIp == "0.0.0.0" && runningOutsideContainer)
            {
                _logger.LogWarning("Your HTTP server is exposed to the public internet, we recommend setting up a reverse proxy and enabling HTTPS");
                _logger.LogWarning("See https://github.com/Impostor/Impostor/blob/master/docs/Http-server.md for instructions");
            }

            _timer = new Timer(TimerCallback, null, TimeSpan.Zero, TimeSpan.FromMinutes(15));
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogWarning("Matchmaker is shutting down!");
            _timer?.Change(Timeout.Infinite, 0);

            await _matchmaker.StopAsync();
        }

        private void TimerCallback(object state)
        {
            try
            {
                if (_httpServerConfig.UseEacCheck)
                {
                    _logger.LogInformation("Checking EAC data and clear mm tokens...");
                    _eacFunctions.UpdateEACListFromURLAsync(_httpServerConfig.EacToken).GetAwaiter().GetResult();  // 更新EACList

                    GamesController.MmTokens.Clear();
                    TokenController.MmRequestFailure.Clear();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occurred in the timer callback: " + ex.Message);
            }
        }
    }
}
