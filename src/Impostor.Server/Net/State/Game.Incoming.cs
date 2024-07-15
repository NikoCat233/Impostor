using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Config;
using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Hazel;
using Impostor.Server.Events;
using Impostor.Server.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
            _logger.LogInformation("{0} - Player {1} was kicked. IsBan: {2}.", Code, playerId, isBan);

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

        private async ValueTask HandleJoinGameNew(ClientPlayer sender, bool isNew)
        {
            _logger.LogInformation("{0} - Player {1} ({2}) is joining from ({3}) with v{4}", Code, sender.Client.Name, sender.Client.Id, sender.Client.Connection.EndPoint.Address + ":" + sender.Client.Connection.EndPoint.Port, sender.Client.GameVersion.ToString());

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
                return GameJoinResult.FromError(GameJoinError.Banned);
            }

            var player = client.Player;

            // Check if the player is running the same version as the host
            if (_compatibilityConfig.AllowVersionMixing == false &&
                this.Host != null && client.GameVersion != this.Host.Client.GameVersion)
            {
                if (client.GameVersion < this.Host.Client.GameVersion)
                {
                    return GameJoinResult.FromError(GameJoinError.ClientOutdated);
                }
                else
                {
                    return GameJoinResult.FromError(GameJoinError.ClientTooNew);
                }
            }

            // Check if;
            // - The player is already in this game.
            // - The game is full.
            if (player?.Game != this && _players.Count >= Options.MaxPlayers)
            {
                return GameJoinResult.FromError(GameJoinError.GameFull);
            }

            if (GameState == GameStates.Starting || GameState == GameStates.Started)
            {
                return GameJoinResult.FromError(GameJoinError.GameStarted);
            }

            if (GameState == GameStates.Destroyed)
            {
                return GameJoinResult.FromError(GameJoinError.GameDestroyed);
            }

            var isNew = false;

            if (player == null || player.Game != this)
            {
                var clientPlayer = new ClientPlayer(_serviceProvider.GetRequiredService<ILogger<ClientPlayer>>(), client, this);

                if (!_clientManager.Validate(client))
                {
                    return GameJoinResult.FromError(GameJoinError.InvalidClient);
                }

                isNew = true;
                player = clientPlayer;
                client.Player = clientPlayer;
            }

            // Check current player state.
            if (player.Limbo == LimboStates.NotLimbo)
            {
                return GameJoinResult.FromError(GameJoinError.InvalidLimbo);
            }

            var clientIp = client.Connection.EndPoint.Address.ToString();
            var matchingUser = TokenController.AuthClientData.Where(x => !x.Used && x.Name == client.Name && (x.PreIp == clientIp || _tokenController.CustomCompareIps(x.PreIp, x.RealIp))).FirstOrDefault();

            if (player.Client.Puid == string.Empty)
            {
                if (matchingUser != null)
                {
                    if (matchingUser.CreatedAt < DateTime.UtcNow.AddMinutes(-1))
                    {
                        matchingUser.Used = true;
                        TokenController.AuthClientData.Remove(matchingUser);
                        return GameJoinResult.CreateCustomError("[NikoCat233]\nTimeout Auth.\nPlease Retry Login.\n<nobr><link=\"https://au.niko233.me/trouble_en.html\">See Trouble Shooting</nobr></link> ");
                    }

                    matchingUser.Used = true;
                    matchingUser.RealIp = clientIp;
                    player.Client.Puid = matchingUser.Puid;
                    player.Client.FriendCode = matchingUser.FriendCode;
                    _logger.LogInformation("{0} - Player {1} ({2}) is assigned puid as {3} ({4}) from http ip ({5}), real ip ({6})", Code, client.Name, client.Id, TokenController.HashedPuid(player.Client.Puid), client.FriendCode, matchingUser.PreIp, client.Connection.EndPoint.Address);
                }
                else if (_antiCheatConfig.ForceAuthOrKick)
                {
                    _logger.LogWarning("{0} - Player {1} ({2}) ({3}) is not assigned a puid. Kicking.", Code, client.Name, client.Id, clientIp);
                    return GameJoinResult.CreateCustomError("[NikoCat233]\nServer cannot auth you. Try disable your proxy!\nIf you are on Moblie Data, try turn on and off Flight Mode and retry login.\n<nobr><link=\"https://au.niko233.me/trouble_en.html\">See Trouble Shooting</nobr></link> ");
                }
                else
                {
                    _logger.LogWarning("{0} - Player {1} ({2}) ({3}) is not assigned a puid. Still letting it in.", Code, client.Name, client.Id, clientIp);
                }
            }

            if (client.Puid != string.Empty)
            {
                if (_httpServerConfig.UseEacCheck && (_tokenController._eacFunctions.CheckHashPUIDExists(TokenController.HashedPuid(client.Puid)) || _tokenController._eacFunctions.CheckFriendCodeExists(client.FriendCode.ToLower())))
                {
                    _logger.LogInformation(Code + " - Player " + client.Name + " (" + client.Id + ") is eac banned previously.");
                    return GameJoinResult.CreateCustomError(string.Format("[Impostor Anticheat+]\nYou are banned by EAC previously.\n {0}", TokenController.HashedPuid(client.Puid) + " " + client.FriendCode.ToLower()));
                }

                if (_bannedPuids.Contains(client.Puid))
                {
                    _logger.LogInformation(Code + " - Player " + client.Name + " (" + client.Id + ") is puid banned previously.");
                    return GameJoinResult.FromError(GameJoinError.Banned);
                }
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

            await HandleJoinGameNew(player, isNew);
            return GameJoinResult.CreateSuccess(player);
        }

        private async ValueTask HandleJoinGameNext(ClientPlayer sender, bool isNew)
        {
            _logger.LogInformation("{0} - Player {1} ({2}) is rejoining from ({3}) with v{4}", Code, sender.Client.Name, sender.Client.Id, sender.Client.Connection.EndPoint.Address + ":" + sender.Client.Connection.EndPoint.Port, sender.Client.GameVersion.ToString());

            // Add player to the game.
            if (isNew)
            {
                await PlayerAdd(sender);
            }

            // Check if the host joined and let everyone join.
            if (sender.Client.Id == HostId)
            {
                GameState = GameStates.NotStarted;

                // Spawn the host.
                await HandleJoinGameNew(sender, false);

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
