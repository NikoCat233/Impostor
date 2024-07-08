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
        private readonly Timer _dataTimeout;
        private readonly int _dataTimeoutTime;

        public ClientPlayer(ILogger<ClientPlayer> logger, ClientBase client, Game game, int timeOutTime)
        {
            _logger = logger;
            _spawnTimeout = new Timer(RunSpawnTimeout!, null, -1, -1);
            _spawnTimeoutTime = timeOutTime;
            _dataTimeout = new Timer(RunDataTimeOut!, null, -1, -1);
            _dataTimeoutTime = timeOutTime;

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

        public void InitializeDataTimeout()
        {
            _dataTimeout.Change(_dataTimeoutTime, -1);
        }

        // No need to disable data timeout i think.
        public void DisableDataTimeout()
        {
            _dataTimeout.Change(-1, -1);
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

                    await RemoveAsync(DisconnectReason.Custom, "Host didn't spawn your player in time.");
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

        private async void RunDataTimeOut(object state)
        {
            try
            {
                if (Character == null || Character.PlayerInfo == null)
                {
                    _logger.LogInformation("{0} - Player {1} data timed out, didnt spawn, kicking.", Game.Code, Client.Id);

                    await RemoveAsync(DisconnectReason.Custom, "Host didn't spawn your data in time.");
                    return;
                }

                if (Character.PlayerInfo.CurrentOutfit.IsIncomplete)
                {
                    _logger.LogInformation("{0} - Player {1} data timed out, didnt finish, kicking.", Game.Code, Client.Id);

                    await RemoveAsync(DisconnectReason.Custom, "You didnt finish your data in time.");
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Exception caught while kicking player for data timeout.");
            }
            finally
            {
                await _dataTimeout.DisposeAsync();
            }
        }
    }
}
