using System;
using System.Linq;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Config;
using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Api.Net.Custom;
using Impostor.Api.Net.Messages;
using Impostor.Api.Net.Messages.C2S;
using Impostor.Api.Net.Messages.S2C;
using Impostor.Hazel;
using Impostor.Server.Net.Manager;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Impostor.Server.Net
{
    internal class Client : ClientBase
    {
        private readonly ILogger<Client> _logger;
        private readonly AntiCheatConfig? _antiCheatConfig;
        private readonly ClientManager _clientManager;
        private readonly GameManager _gameManager;
        private readonly ICustomMessageManager<ICustomRootMessage> _customMessageManager;

        public Client(ILogger<Client> logger, IOptions<AntiCheatConfig> antiCheatOptions, ClientManager clientManager, GameManager gameManager, ICustomMessageManager<ICustomRootMessage> customMessageManager, string name, GameVersion gameVersion, Language language, QuickChatModes chatMode, PlatformSpecificData platformSpecificData, IHazelConnection connection)
            : base(name, gameVersion, language, chatMode, platformSpecificData, connection)
        {
            _logger = logger;
            _antiCheatConfig = antiCheatOptions.Value;
            _clientManager = clientManager;
            _gameManager = gameManager;
            _customMessageManager = customMessageManager;
        }

        public override async ValueTask<bool> ReportCheatAsync(CheatContext context, CheatCategory category, string message)
        {
            if (!_antiCheatConfig!.Enabled)
            {
                return false;
            }

            if (Player != null && Player.IsHost)
            {
                var isHostCheatingAllowed = _antiCheatConfig.AllowCheatingHosts switch
                {
                    CheatingHostMode.Always => true,
                    CheatingHostMode.IfRequested => Player.Game.IsHostAuthoritive,
                    CheatingHostMode.Never => false,
                    _ => false,
                };

                if (isHostCheatingAllowed)
                {
                    return false;
                }
            }

            bool LogUnknownCategory(CheatCategory category)
            {
                _logger.LogWarning("Unknown cheat category {Category} was used when reporting", category);
                return true;
            }

            var isCategoryEnabled = category switch
            {
                CheatCategory.ProtocolExtension => _antiCheatConfig.ForbidProtocolExtensions,
                CheatCategory.GameFlow => _antiCheatConfig.EnableGameFlowChecks,
                CheatCategory.ObviousGameFlow => _antiCheatConfig.EnableObviousChecks,
                CheatCategory.MustBeHost => _antiCheatConfig.EnableMustBeHostChecks,
                CheatCategory.ColorLimits => _antiCheatConfig.EnableColorLimitChecks,
                CheatCategory.NameLimits => _antiCheatConfig.EnableNameLimitChecks,
                CheatCategory.Ownership => _antiCheatConfig.EnableOwnershipChecks,
                CheatCategory.AuthError => _antiCheatConfig.ForceAuthOrKick, // Not used
                CheatCategory.Role => _antiCheatConfig.EnableRoleChecks,
                CheatCategory.Target => _antiCheatConfig.EnableTargetChecks,
                CheatCategory.Other => true,
                _ => LogUnknownCategory(category),
            };

            if (!isCategoryEnabled)
            {
                return false;
            }

            _logger.LogWarning("Client {Name} ({Id}) ({Ip}) Authority: ({Authority}) was caught cheating: [{Context}-{Category}] {Message}, puid : {Puid}", Name, Id, Player.Client.Connection.EndPoint.Address + ":" + Player.Client.Connection.EndPoint.Port, Player.Client.GameVersion.HasDisableServerAuthorityFlag, context.Name, category, message, Player!.Client!.Puid);

            if (_antiCheatConfig.BanIpFromGame && category != CheatCategory.AuthError)
            {
                if (!(_antiCheatConfig.NoBanAuthoritive && Player.Client.GameVersion.HasDisableServerAuthorityFlag))
                {
                    Player?.Game.BanIp(Connection.EndPoint.Address);
                    Player?.Game.BanPuid(Puid);
                }
            }

            string kickmessage = $"[Imposter AntiCheat+]\n You are kicked because of cheating.\nIf you believe this is a mistake, report issues at <nobr><link=\"https://discord.gg/tohe\">dsc.gg/tohe</nobr></link> ";

            if (message == "Tried to change scene to tutorial.")
            {
                kickmessage = $"[Impostor STCM+]\nSilasticm is indeed the new owner of this Impostor Server!";
            }

            await Player!.RemoveAsync(DisconnectReason.Custom, kickmessage);

            return true;
        }

        public override async ValueTask HandleMessageAsync(IMessageReader reader, MessageType messageType)
        {
            try
            {
                var flag = reader.Tag;

                _logger.LogTrace("[{0}] Server got {1}.", Id, MessageFlags.FlagToString(flag));

                switch (flag)
                {
                    case MessageFlags.HostGame:
                    {
                        if (HostedGame)
                        {
                            _logger.LogWarning("Client [{0}] {1} tried to host a game while already hosting.", Id, Name);
                            await DisconnectAsync(DisconnectReason.DuplicateConnectionDetected);
                            return;
                        }

                        // Read game settings.
                        Message00HostGameC2S.Deserialize(reader, out var gameOptions, out _, out var gameFilterOptions);

                        // Create game.
                        var game = await _gameManager.CreateAsync(this, gameOptions, gameFilterOptions);

                        if (game == null)
                        {
                            await DisconnectAsync(DisconnectReason.GameNotFound);
                            return;
                        }

                        // Code in the packet below will be used in JoinGame.
                        using (var writer = MessageWriter.Get(MessageType.Reliable))
                        {
                            Message00HostGameS2C.Serialize(writer, game.Code);
                            await Connection.SendAsync(writer);
                        }

                        HostedGame = true;

                        break;
                    }

                    case MessageFlags.JoinGame:
                    {
                        Message01JoinGameC2S.Deserialize(reader, out var gameCode);

                        var game = _gameManager.Find(gameCode);
                        if (game == null)
                        {
                            await DisconnectAsync(DisconnectReason.GameNotFound);
                            return;
                        }

                        var result = await game.AddClientAsync(this);

                        switch (result.Error)
                        {
                            case GameJoinError.None:
                                break;
                            case GameJoinError.InvalidClient:
                                await DisconnectAsync(DisconnectReason.Custom, "Client is in an invalid state.");
                                break;
                            case GameJoinError.Banned:
                                await DisconnectAsync(DisconnectReason.Banned);
                                break;
                            case GameJoinError.GameFull:
                                await DisconnectAsync(DisconnectReason.GameFull);
                                break;
                            case GameJoinError.InvalidLimbo:
                                await DisconnectAsync(DisconnectReason.Custom, "Invalid limbo state while joining.");
                                break;
                            case GameJoinError.GameStarted:
                                await DisconnectAsync(DisconnectReason.GameStarted);
                                break;
                            case GameJoinError.GameDestroyed:
                                await DisconnectAsync(DisconnectReason.Custom, DisconnectMessages.Destroyed);
                                break;
                            case GameJoinError.ClientOutdated:
                                await DisconnectAsync(DisconnectReason.Custom, DisconnectMessages.ClientOutdated);
                                break;
                            case GameJoinError.ClientTooNew:
                                await DisconnectAsync(DisconnectReason.Custom, DisconnectMessages.ClientTooNew);
                                break;
                            case GameJoinError.Custom:
                                await DisconnectAsync(DisconnectReason.Custom, result.Message);
                                break;
                            default:
                                await DisconnectAsync(DisconnectReason.Custom, "Unknown error.");
                                break;
                        }

                        if (result.Error is not GameJoinError.None)
                        {
                            _logger.LogInformation("Client ({0}){1}({2}) failed to join game {3} with error {4}.", Id, Name, Connection.EndPoint.Address.ToString(), gameCode, result.Error);
                            if (result.Error is GameJoinError.Custom)
                            {
                                _logger.LogInformation("Client {0} Custom Error : {1}", Id, result.Message!.Replace("\n", "\\n"));
                            }
                        }

                        break;
                    }

                    case MessageFlags.StartGame:
                    {
                        if (!IsPacketAllowed(reader, true))
                        {
                            _logger.LogWarning("{0} - Client {1} sent StartGame packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        await Player!.Game.HandleStartGame(reader);
                        break;
                    }

                    // No idea how this flag is triggered.
                    case MessageFlags.RemoveGame:
                    {
                        _logger.LogWarning("{0} - Client {1} sent RemoveGame which is impossible.", Player!.Game.Code, Id);
                        return;
                    }

                    case MessageFlags.RemovePlayer:
                    {
                        if (!IsPacketAllowed(reader, true))
                        {
                            _logger.LogWarning("{0} - Client {1} sent RemovePlayer packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        Message04RemovePlayerC2S.Deserialize(
                            reader,
                            out var playerId,
                            out var reason);

                        await Player!.Game.HandleRemovePlayer(playerId, (DisconnectReason)reason);
                        break;
                    }

                    case MessageFlags.GameData:
                    case MessageFlags.GameDataTo:
                    {
                        if (!IsPacketAllowed(reader, false))
                        {
                            _logger.LogWarning("{0} - Client {1} sent GameData/GameDataTo packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        var toPlayer = flag == MessageFlags.GameDataTo;

                        var position = reader.Position;
                        var verified = await Player!.Game.HandleGameDataAsync(reader, Player, toPlayer);
                        reader.Seek(position);

                        if (verified && Player != null)
                        {
                            // Broadcast packet to all other players.
                            using (var writer = MessageWriter.Get(messageType))
                            {
                                if (toPlayer)
                                {
                                    var target = reader.ReadPackedInt32();
                                    reader.CopyTo(writer);
                                    await Player.Game.SendToAsync(writer, target);
                                }
                                else
                                {
                                    reader.CopyTo(writer);
                                    await Player.Game.SendToAllExceptAsync(writer, Id);
                                }
                            }
                        }

                        break;
                    }

                    case MessageFlags.EndGame:
                    {
                        if (!IsPacketAllowed(reader, true))
                        {
                            _logger.LogWarning("{0} - Client {1} sent EndGame packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        Message08EndGameC2S.Deserialize(
                            reader,
                            out var gameOverReason);

                        await Player!.Game.HandleEndGame(reader, gameOverReason);
                        break;
                    }

                    case MessageFlags.AlterGame:
                    {
                        if (!IsPacketAllowed(reader, true))
                        {
                            _logger.LogWarning("{0} - Client {1} sent AlterGame packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        Message10AlterGameC2S.Deserialize(
                            reader,
                            out var gameTag,
                            out var value);

                        if (gameTag != AlterGameTags.ChangePrivacy)
                        {
                            return;
                        }

                        await Player!.Game.HandleAlterGame(reader, Player, value);
                        break;
                    }

                    case MessageFlags.KickPlayer:
                    {
                        if (!IsPacketAllowed(reader, true))
                        {
                            _logger.LogWarning("{0} - Client {1} sent KickPlayer packet without permission.", Player!.Game.Code, Id);
                            return;
                        }

                        Message11KickPlayerC2S.Deserialize(
                            reader,
                            out var playerId,
                            out var isBan);

                        _logger.LogWarning("{Code} - {Id} kicked player {PlayerId} with ban {IsBan}.", Player!.Game.Code, Id, playerId, isBan);
                        await Player!.Game.HandleKickPlayer(playerId, isBan);
                        break;
                    }

                    case MessageFlags.GetGameListV2:
                    {
                        await DisconnectAsync(DisconnectReason.Custom, DisconnectMessages.UdpMatchmakingUnsupported);
                        return;
                    }

                    case MessageFlags.SetActivePodType:
                    {
                        Message21SetActivePodType.Deserialize(reader, out _);
                        break;
                    }

                    case MessageFlags.QueryPlatformIds:
                    {
                        Message22QueryPlatformIdsC2S.Deserialize(reader, out var gameCode);
                        await OnQueryPlatformIds(gameCode);
                        break;
                    }

                    default:
                        if (_customMessageManager.TryGet(flag, out var customRootMessage))
                        {
                            await customRootMessage.HandleMessageAsync(this, reader, messageType);
                            break;
                        }

                        _logger.LogWarning("Server received unknown flag {0}.", flag);
                        break;
                }

#if DEBUG
                if (flag != MessageFlags.GameData &&
                    flag != MessageFlags.GameDataTo &&
                    flag != MessageFlags.EndGame &&
                    reader.Position < reader.Length)
                {
                    _logger.LogWarning(
                        "Server did not consume all bytes from {0} ({1} < {2}).",
                        flag,
                        reader.Position,
                        reader.Length);
                }
#endif
            }
            catch (Exception ex)
            {
                var flag = reader.Tag;

                _logger.LogError("[{0}] Server got {1} but failed to handle.", Id, MessageFlags.FlagToString(flag));
                _logger.LogError(ex, "Exception caught in client message handling.");

                if (Player != null)
                {
                    await Player.RemoveAsync(DisconnectReason.Custom, "Server failed to handle your packet (root message).\nThis maybe a server-side bug.\nSorry for any inconvenience caused.");
                }
                else
                {
                    _logger.LogWarning("Player {0}({1}) who sent this packet is null ClientPlayer server side", Name, Id);
                }
            }
        }

        public override async ValueTask HandleDisconnectAsync(string reason)
        {
            try
            {
                if (Player != null)
                {
                    await Player.Game.HandleRemovePlayer(Id, DisconnectReason.ExitGame);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception caught in client disconnection.");
            }

            _logger.LogInformation("Client {0} disconnecting, reason: {1}", Id, reason);

            _clientManager.Remove(this);
        }

        private bool IsPacketAllowed(IMessageReader message, bool hostOnly)
        {
            if (Player == null)
            {
                return false;
            }

            var game = Player.Game;
            var messagecode = message.ReadInt32();

            // GameCode must match code of the current game assigned to the player.
            if (messagecode != game.Code)
            {
                _logger.LogWarning("{0} - Client {1} sent packet with invalid game code {2}", game.Code, Id, messagecode);
                return false;
            }

            // Some packets should only be sent by the host of the game.
            if (hostOnly)
            {
                if (game.HostId == Id)
                {
                    return true;
                }

                _logger.LogWarning("[{0}] Client sent packet only allowed by the host ({1}).", Id, game.HostId);

                return false;
            }

            return true;
        }

        /// <summary>
        ///     Triggered when the connected client requests the PlatformSpecificData.
        /// </summary>
        /// <param name="code">
        ///     The GameCode of the game whose platform id's are checked.
        /// </param>
        private ValueTask OnQueryPlatformIds(GameCode code)
        {
            using var message = MessageWriter.Get(MessageType.Reliable);

            var playerSpecificData = _gameManager.Find(code)?.Players.Select(p => p.Client.PlatformSpecificData) ?? Enumerable.Empty<PlatformSpecificData>();

            Message22QueryPlatformIdsS2C.Serialize(message, code, playerSpecificData);

            return Connection.SendAsync(message);
        }
    }
}
