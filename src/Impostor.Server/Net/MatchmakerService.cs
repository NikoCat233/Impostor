using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Config;
using Impostor.Server.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;

namespace Impostor.Server.Net
{
    internal class MatchmakerService : IHostedService
    {
        private readonly ILogger<MatchmakerService> _logger;
        private readonly ServerConfig _serverConfig;
        private readonly HttpServerConfig _httpServerConfig;
        private readonly Matchmaker _matchmaker;
        private readonly TokenController _tokenController;
        private readonly EacController.EACFunctions _eACFunctions;
        private readonly Timer _timerTask;

        public MatchmakerService(
            ILogger<MatchmakerService> logger,
            IOptions<ServerConfig> serverConfig,
            IOptions<HttpServerConfig> httpServerConfig,
            Matchmaker matchmaker,
            TokenController tokenController,
            EacController.EACFunctions eACFunctions)
        {
            _logger = logger;
            _serverConfig = serverConfig.Value;
            _httpServerConfig = httpServerConfig.Value;
            _matchmaker = matchmaker;
            _tokenController = tokenController;
            _eACFunctions = eACFunctions;
            _timerTask = new Timer(TimerCallback!, null, TimeSpan.Zero, TimeSpan.FromSeconds(180));
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

            _logger.LogInformation("This build of Impostor is modified by NikoCat233, do not share or spread. Thank you!");
            _logger.LogInformation("QQ: 1529729259;  Github: NikoCat233; Website: au.niko233.me");

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
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogWarning("Matchmaker is shutting down!");
            _logger.LogInformation("This build of Impostor is modified by NikoCat233, do not share or spread. Thank you!");
            _logger.LogInformation("QQ: 1529729259;  Github: NikoCat233; Website: au.niko233.me");
            await _matchmaker.StopAsync();
        }

        private void TimerCallback(object state)
        {
            try
            {
                if (_httpServerConfig.UseEacCheck)
                {
                    _eACFunctions.UpdateEACListFromURLAsync("NikoCat233_Is_Impostor").GetAwaiter().GetResult();  // Update EACList
                }

                if (_httpServerConfig.UseInnerSlothAuth)
                {
                    foreach (var tokens in TokenController.AuthClientData)
                    {
                        if (tokens.Used)
                        {
                            TokenController.AuthClientData.Remove(tokens);
                            continue;
                        }

                        if (tokens.CreatedAt < DateTime.UtcNow.AddMinutes(-3))
                        {
                            tokens.Used = true;
                            TokenController.AuthClientData.Remove(tokens);
                            continue;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occurred in the timer callback: " + ex.Message);
            }
        }
    }
}
