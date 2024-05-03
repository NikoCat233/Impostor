using System;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Api.Net.Inner;
using Impostor.Api.Unity;
using Impostor.Server.Net.Inner.Objects;
using Microsoft.Extensions.Logging;

namespace Impostor.Server.Net.State
{
    internal partial class ClientPlayer : IClientPlayer
    {
        private readonly ILogger<ClientPlayer> _logger;
        private readonly Timer _spawnTimeout;
        private readonly int _spawnTimeoutTime;

        public ClientPlayer(ILogger<ClientPlayer> logger, ClientBase client, Game game, int timeOutTime)
        {
            _logger = logger;
            _spawnTimeout = new Timer(RunSpawnTimeout!, null, -1, -1);
            _spawnTimeoutTime = timeOutTime;

            Game = game;
            Client = client;
            Limbo = LimboStates.PreSpawn;
        }

        public ClientBase Client { get; }

        public Game Game { get; }

        /// <inheritdoc />
        public LimboStates Limbo { get; set; }

        public InnerPlayerControl? Character { get; internal set; }

        public bool IsHost => Game?.Host == this;

        public string? Scene { get; internal set; }

        public RuntimePlatform? Platform { get; internal set; }

        public void InitializeSpawnTimeout()
        {
            _spawnTimeout.Change(_spawnTimeoutTime, -1);
        }

        public void DisableSpawnTimeout()
        {
            _spawnTimeout.Change(-1, -1);
        }

        /// <inheritdoc />
        public bool IsOwner(IInnerNetObject netObject)
        {
            return Client.Id == netObject.OwnerId;
        }

        /// <inheritdoc />
        public ValueTask KickAsync()
        {
            return Game.HandleKickPlayer(Client.Id, false);
        }

        /// <inheritdoc />
        public ValueTask BanAsync()
        {
            return Game.HandleKickPlayer(Client.Id, true);
        }

        public async ValueTask RemoveAsync(DisconnectReason reason, string custom = "")
        {
            await Game.HandleRemovePlayer(Client.Id, reason);
            await Client.DisconnectAsync(reason, custom);
        }

        private async void RunSpawnTimeout(object state)
        {
            try
            {
                if (Character == null)
                {
                    _logger.LogInformation("{0} - Player {1} spawn timed out, kicking.", Game.Code, Client.Id);

                    await RemoveAsync(DisconnectReason.Custom, "[Impostor AntiCheat+] Host didn't spawn you in time\nMaybe Host is too laggy?\nReport issues to your host or Seek help at <nobr><link=\"https://discord.gg/tohe\">dsc.gg/tohe</nobr></link>");
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Exception caught while kicking player for spawn timeout.");
            }
            finally
            {
                await _spawnTimeout.DisposeAsync();
            }
        }
    }
}
