using System.Linq;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Hazel;
using Impostor.Server.Events;
using Impostor.Server.Net.Hazel;
using Microsoft.Extensions.Logging;

namespace Impostor.Server.Net.State
{
    internal partial class Game
    {
        private async ValueTask PlayerAdd(ClientPlayer player)
        {
            // Store player.
            if (!_players.TryAdd(player.Client.Id, player))
            {
                throw new ImpostorException("Failed to add player to game.");
            }

            // Assign hostId if none is set.
            if (HostId == -1)
            {
                HostId = player.Client.Id;
            }

            await _eventManager.CallAsync(new GamePlayerJoinedEvent(this, player));
        }

        private async ValueTask<bool> PlayerRemove(int playerId, bool isBan = false)
        {
            if (!_players.TryRemove(playerId, out var player))
            {
                return false;
            }

            _logger.LogInformation("{0} - Player {1} ({2}) has left. hashpuid : {3}", Code, player.Client.Name, playerId, player.Client.HashedPuid());

            if (GameState == GameStates.Starting || GameState == GameStates.Started || GameState == GameStates.NotStarted)
            {
                if (player.Character?.PlayerInfo != null)
                {
                    player.Character.PlayerInfo.Disconnected = true;
                    player.Character.PlayerInfo.LastDeathReason = DeathReason.Disconnect;
                }
            }

            player.Client.Player = null;

            // Host migration.
            if (HostId == playerId)
            {
                await MigrateHost();
                await _eventManager.CallAsync(new GameHostChangedEvent(this, player, Host));
            }

            // Game is empty, remove it.
            if (_players.IsEmpty || Host == null)
            {
                GameState = GameStates.Destroyed;

                // Remove instance reference.
                await _gameManager.RemoveAsync(Code);
                return true;
            }

            if (isBan)
            {
                BanIp(player.Client.Connection.EndPoint.Address);
                BanPuid(player.Client.Puid);
            }

            await _eventManager.CallAsync(new GamePlayerLeftEvent(this, player, isBan));

            // Player can refuse to be kicked and keep the connection open, check for this.
            _ = Task.Run(async () =>
            {
                await Task.Delay(_timeoutConfig.ConnectionTimeout);

                if (player.Client.Connection.IsConnected && player.Client.Connection is HazelConnection hazel)
                {
                    _logger.LogInformation("{0} - Player {1} ({2}) kept connection open after leaving, disposing.", Code, player.Client.Name, playerId);
                    await player.Client.DisconnectAsync(isBan ? DisconnectReason.Banned : DisconnectReason.Kicked);
                }
            });

            // Clean up the PlayerInfo if we own it
            foreach (var playerInfo in GameNet.GameData.Players.Values)
            {
                if (playerInfo.ClientId == playerId)
                {
                    if (playerInfo.OwnerId == ServerOwned)
                    {
                        _logger.LogInformation("Destroying PlayerInfo {nid}", playerInfo.NetId);
                        GameNet.GameData.RemovePlayer(playerInfo.PlayerId);
                        RemoveNetObject(playerInfo);

                        await SendObjectDespawn(playerInfo);
                    }

                    break;
                }
            }

            return true;
        }

        private async ValueTask MigrateHost()
        {
            // Pick the first player as new host.
            var host = _players
                .Select(p => p.Value)
                .Where(x => x.Client.GameVersion.HasDisableServerAuthorityFlag)
                .FirstOrDefault();

            if (host == null)
            {
                host = _players
                .Select(p => p.Value)
                .FirstOrDefault();

                if (host == null)
                {
                    return;
                }
            }

            foreach (var player in _players.Values)
            {
                player.Character?.RequestedPlayerName.Clear();
                player.Character?.RequestedColorId.Clear();
            }

            HostId = host.Client.Id;
            _logger.LogInformation("{0} - Assigned {1} ({2}) as new host. Player Authority : {3}, Room Authority : {4}", Code, host.Client.Name, host.Client.Id, host.Client.GameVersion.HasDisableServerAuthorityFlag, IsHostAuthoritive);

            // Check our current game state.
            if (GameState == GameStates.Ended && host.Limbo == LimboStates.WaitingForHost)
            {
                GameState = GameStates.NotStarted;

                // Spawn the host.
                await HandleJoinGameNew(host, false);

                // Pull players out of limbo.
                await CheckLimboPlayers();
            }
        }

        private async ValueTask CheckLimboPlayers()
        {
            using var message = MessageWriter.Get(MessageType.Reliable);

            foreach (var (_, player) in _players.Where(x => x.Value.Limbo == LimboStates.WaitingForHost))
            {
                WriteJoinedGameMessage(message, true, player);
                WriteAlterGameMessage(message, false, IsPublic);

                player.Limbo = LimboStates.NotLimbo;
                _sentOnlineGameClients.Remove(player.Client.Id);

                await SendToAsync(message, player.Client.Id);
            }
        }
    }
}
