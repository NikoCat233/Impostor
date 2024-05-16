using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Hazel;
using Impostor.Server.Events;
using Impostor.Server.Net.Manager;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using static Impostor.Server.Http.TokenController;

namespace Impostor.Server.Net.State
{
    internal partial class Game
    {
        private readonly SemaphoreSlim _clientAddLock = new SemaphoreSlim(1, 1);

        public async ValueTask HandleStartGame(IMessageReader message)
        {
            GameState = GameStates.Starting;

            using var packet = MessageWriter.Get(MessageType.Reliable);
            message.CopyTo(packet);
            await SendToAllAsync(packet);

            await _eventManager.CallAsync(new GameStartingEvent(this));

            _logger.LogInformation("Game {Code} started, Host is {Host}, Room Authority : {Authority}", Code, Host.Client.Name, IsHostAuthoritive);
        }

        public async ValueTask HandleEndGame(IMessageReader message, GameOverReason gameOverReason)
        {
            GameState = GameStates.Ended;

            // Broadcast end of the game.
            using (var packet = MessageWriter.Get(MessageType.Reliable))
            {
                message.CopyTo(packet);
                await SendToAllAsync(packet);
            }

            _logger.LogInformation("Game {Code} ended, Host is {Host}, Room Authority : {Authority}", Code, Host.Client.Name, IsHostAuthoritive);

            // Put all players in the correct limbo state.
            foreach (var player in _players)
            {
                player.Value.Limbo = LimboStates.PreSpawn;
            }

            await _eventManager.CallAsync(new GameEndedEvent(this, gameOverReason));
        }

        public async ValueTask HandleAlterGame(IMessageReader message, IClientPlayer sender, bool isPublic)
        {
            IsPublic = isPublic;

            using var packet = MessageWriter.Get(MessageType.Reliable);
            message.CopyTo(packet);
            await SendToAllExceptAsync(packet, sender.Client.Id);

            await _eventManager.CallAsync(new GameAlterEvent(this, isPublic));
        }

        public async ValueTask HandleRemovePlayer(int playerId, DisconnectReason reason)
        {
            await PlayerRemove(playerId);

            // It's possible that the last player was removed, so check if the game is still around.
            if (GameState == GameStates.Destroyed)
            {
                return;
            }

            using var packet = MessageWriter.Get(MessageType.Reliable);
            WriteRemovePlayerMessage(packet, false, playerId, reason);
            await SendToAllExceptAsync(packet, playerId);
        }

        public async ValueTask HandleKickPlayer(int playerId, bool isBan)
        {
            _logger.LogInformation("{0} - Player {1} has been {2}.", Code, playerId, isBan ? "Banned" : "Kicked");

            using var message = MessageWriter.Get(MessageType.Reliable);

            // Send message to everyone that this player was kicked.
            WriteKickPlayerMessage(message, false, playerId, isBan);

            await SendToAllAsync(message);
            await PlayerRemove(playerId, isBan);

            // Remove the player from everyone's game.
            WriteRemovePlayerMessage(
                message,
                true,
                playerId,
                isBan ? DisconnectReason.Banned : DisconnectReason.Kicked);

            await SendToAllExceptAsync(message, playerId);
        }

        public async ValueTask<GameJoinResult> AddClientAsync(ClientBase client)
        {
            var hasLock = false;

            try
            {
                hasLock = await _clientAddLock.WaitAsync(TimeSpan.FromMinutes(1));

                if (hasLock)
                {
                    return await AddClientSafeAsync(client);
                }
            }
            finally
            {
                if (hasLock)
                {
                    _clientAddLock.Release();
                }
            }

            return GameJoinResult.FromError(GameJoinError.InvalidClient);
        }

        private async ValueTask HandleJoinGameNewAsync(ClientPlayer sender, bool isNew)
        {
            _logger.LogInformation("{0} - Player {1} ({2}) ({3}) is joining from ({4}) with v{5}, Authority:{6}", Code, sender.Client.Name, sender.Client.HashedPuid(), sender.Client.Id, sender.Client.Connection.EndPoint.Address + ":" + sender.Client.Connection.EndPoint.Port, sender.Client.GameVersion.ToString(), sender.Client.GameVersion.HasDisableServerAuthorityFlag);

            // Should only happen on first player join(Host).
            if (_decidedAuthoritive == false)
            {
                if (sender.Client.GameVersion.HasDisableServerAuthorityFlag)
                {
                    _authoritive = true;
                    _logger.LogInformation("{0} - Enabled Authoritive by Player {1} ({2})", Code, sender.Client.Name, sender.Client.Id);
                }
                else
                {
                    _authoritive = false;
                    _logger.LogInformation("{0} - Run on Vanilla by Player {1} ({2})", Code, sender.Client.Name, sender.Client.Id);
                }

                _decidedAuthoritive = true;
            }

            _decidedAuthoritive = true;

            // Add player to the game.
            if (isNew)
            {
                await PlayerAdd(sender);
            }

            sender.InitializeSpawnTimeout();

            using (var message = MessageWriter.Get(MessageType.Reliable))
            {
                WriteJoinedGameMessage(message, false, sender);
                WriteAlterGameMessage(message, false, IsPublic);

                sender.Limbo = LimboStates.NotLimbo;

                await SendToAsync(message, sender.Client.Id);
                await BroadcastJoinMessage(message, true, sender);
            }
        }

        private async ValueTask<GameJoinResult> AddClientSafeAsync(ClientBase client)
        {
            // Check if the IP of the player is banned.
            if (_bannedIps.Contains(client.Connection.EndPoint.Address))
            {
                _logger.LogInformation(Code + " - Player " + client.Name + " (" + client.Id + ") is ip banned previously.");
                return GameJoinResult.FromError(GameJoinError.Banned);
            }

            var player = client.Player;

            // Check if the player is running the same version as the host
            if (_compatibilityConfig.AllowVersionMixing == false &&
                this.Host != null && client.GameVersion != Host.Client.GameVersion)
            {
                var versionCheckResult = _compatibilityManager.CanJoinGame(Host.Client.GameVersion, client.GameVersion);
                if (versionCheckResult != GameJoinError.None)
                {
                    return GameJoinResult.FromError(versionCheckResult);
                }
            }

            if (GameState == GameStates.Starting || GameState == GameStates.Started)
            {
                return GameJoinResult.FromError(GameJoinError.GameStarted);
            }

            if (GameState == GameStates.Destroyed)
            {
                return GameJoinResult.FromError(GameJoinError.GameDestroyed);
            }

            // Rejoining clients need to bypass this limit with isNew
            if (Client._antiCheatConfig!.MaxOnlineFromSameIp != 0)
            {
                var count = _clientManager.Clients.Count(x => x.Connection.EndPoint.Address.ToString() == client.Connection.EndPoint.Address.ToString() && x.Connection.IsConnected);

                if (count > Client._antiCheatConfig!.MaxOnlineFromSameIp)
                {
                    _logger.LogInformation("Client {0} ({1}) x {2} reached max clients online IP limit. Kicked.", client.Name, client.Connection.EndPoint.Address.ToString(), count);
                    return GameJoinResult.CreateCustomError(string.Format("[Impostor Anticheat+]\nToo many clients from a same ip.\n({0}) x {1}", client.Connection.EndPoint.Address.ToString(), count));
                }

                if (client.Puid != string.Empty)
                {
                    if (ClientManager._puids.TryGetValue(client.Puid, out var existingToken))
                    {
                        var count2 = existingToken.Clients.Count();
                        if (count2 > Client._antiCheatConfig!.MaxOnlineFromSameIp)
                        {
                            _logger.LogInformation("Client {0} ({1}) x {2} reached max clients online Puid limit. Kicked.", client.Name, client.Connection.EndPoint.Address.ToString(), count);
                            return GameJoinResult.CreateCustomError(string.Format("[Impostor Anticheat+]\nToo many clients from a same puid.\n({0}) x {1}", client.HashedPuid().ToString(), count));
                        }
                    }
                }
            }

            // Check if;
            // - The player is already in this game.
            // - The game is full.
            if (player?.Game != this && _players.Count >= Options.MaxPlayers)
            {
                return GameJoinResult.FromError(GameJoinError.GameFull);
            }

            var isNew = false;

            if (player == null || player.Game != this)
            {
                var clientPlayer = new ClientPlayer(_serviceProvider.GetRequiredService<ILogger<ClientPlayer>>(), client, this, _timeoutConfig.SpawnTimeout);

                if (!_clientManager.Validate(client))
                {
                    return GameJoinResult.FromError(GameJoinError.InvalidClient);
                }

                isNew = true;
                player = clientPlayer;
                client.Player = clientPlayer;
            }

            var clientIp = client.Connection.EndPoint.Address.ToString();
            var matchedPuidEntry = ClientManager._puids.FirstOrDefault(p => p.Value.Ips.Contains(clientIp));

            // We can not handle the case where a user connect to server with 2 different account from a same ip.
            // If it happens, we should reject it while doing token response. Code here will always return the first puid-token generated
            if (matchedPuidEntry.Value != null)
            {
                var authData = matchedPuidEntry.Value;
                client.Puid = matchedPuidEntry.Key;
                client.FriendCode = authData.FriendCode;
                _logger.LogInformation("{0} - Player {1} ({2}) is assigned puid as {3} ({4})", Code, client.Name, client.Id, client.HashedPuid(), client.FriendCode);
            }
            else
            {
                client.Puid = string.Empty;
                client.FriendCode = string.Empty;

                if (Client._antiCheatConfig!.ForceAuthenticationOrKick)
                {
                    _logger.LogWarning("{0} - Player {1} ({2}) is not assigned a puid. Kicking player.", Code, client.Name, client.Id);
                    return GameJoinResult.CreateCustomError("[Imposter Anticheat+]\nServer cannot auth you. Try disable your http proxy!\nIf this still happens, seek help at <nobr><link=\"https://discord.gg/tohe\">dsc.gg/tohe</nobr></link> ");
                }

                _logger.LogWarning("{0} - Player {1} ({2}) is not assigned a puid. Still letting it in.", Code, client.Name, client.Id);
            }

            if (client.Puid != string.Empty)
            {
                if (MatchmakerService._httpServerConfig.UseEacCheck && MatchmakerService._eacFunctions.CheckHashPUIDExists(client.Puid))
                {
                    _logger.LogInformation(Code + " - Player " + client.Name + " (" + client.Id + ") is eac banned previously.");
                    return GameJoinResult.CreateCustomError(string.Format("[Impostor Anticheat+]\nYou are banned by EAC previously.\n {0}", client.HashedPuid()));
                }

                if (_bannedPuids.Contains(client.Puid))
                {
                    _logger.LogInformation(Code + " - Player " + client.Name + " (" + client.Id + ") is puid banned previously.");
                    return GameJoinResult.FromError(GameJoinError.Banned);
                }
            }

            // Check current player state.
            if (player.Limbo == LimboStates.NotLimbo)
            {
                return GameJoinResult.FromError(GameJoinError.InvalidLimbo);
            }

            if (GameState == GameStates.Ended)
            {
                await HandleJoinGameNext(player, isNew);
                return GameJoinResult.CreateSuccess(player);
            }

            var @event = new GamePlayerJoiningEvent(this, player);
            await _eventManager.CallAsync(@event);

            if (@event.JoinResult != null && !@event.JoinResult.Value.IsSuccess)
            {
                return @event.JoinResult.Value;
            }

            await HandleJoinGameNewAsync(player, isNew);
            return GameJoinResult.CreateSuccess(player);
        }

        private async ValueTask HandleJoinGameNext(ClientPlayer sender, bool isNew)
        {
            _logger.LogInformation("{0} - Player {1} ({2}) is rejoining. Player Authority : {3}", Code, sender.Client.Name, sender.Client.Id, sender.Client.GameVersion.HasDisableServerAuthorityFlag);

            // Add player to the game.
            if (isNew)
            {
                await PlayerAdd(sender);
            }

            // Check if the host joined and let everyone join.
            if (sender.Client.Id == HostId)
            {
                _logger.LogInformation("{0} - Host {1} ({2}) rejoined. Room Authority : {3}", Code, sender.Client.Name, sender.Client.Id, IsHostAuthoritive);
                GameState = GameStates.NotStarted;

                _errroVL.Clear();

                // Spawn the host.
                await HandleJoinGameNewAsync(sender, false);

                // Pull players out of limbo.
                await CheckLimboPlayers();
                return;
            }

            sender.Limbo = LimboStates.WaitingForHost;

            using (var packet = MessageWriter.Get(MessageType.Reliable))
            {
                WriteWaitForHostMessage(packet, false, sender);

                await SendToAsync(packet, sender.Client.Id);
                await BroadcastJoinMessage(packet, true, sender);
            }
        }
    }
}
