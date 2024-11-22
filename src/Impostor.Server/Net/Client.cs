using System;
using System.Linq;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Config;
using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Api.Net.Custom;
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
        private readonly AntiCheatConfig _antiCheatConfig;
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
            if (!_antiCheatConfig.Enabled)
            {
                return false;
            }

            if (Player != null && Player.IsHost)
            {
                var isHostCheatingAllowed = _antiCheatConfig.AllowCheatingHosts switch {
                    CheatingHostMode.Always => true,
                    CheatingHostMode.IfRequested => GameVersion.HasDisableServerAuthorityFlag,
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
                CheatCategory.MustBeHost => _antiCheatConfig.EnableMustBeHostChecks,
                CheatCategory.ColorLimits => _antiCheatConfig.EnableColorLimitChecks,
                CheatCategory.NameLimits => _antiCheatConfig.EnableNameLimitChecks,
                CheatCategory.Ownership => _antiCheatConfig.EnableOwnershipChecks,
                CheatCategory.Role => _antiCheatConfig.EnableRoleChecks,
                CheatCategory.Target => _antiCheatConfig.EnableTargetChecks,
                CheatCategory.Other => true,
                _ => LogUnknownCategory(category),
            };

            if (!isCategoryEnabled)
            {
                return false;
            }

            var supportCode = Random.Shared.Next(0, 999_999).ToString("000-000");

            _logger.LogWarning("Client {Name} ({Id}) was caught cheating: [{SupportCode}] [{Context}-{Category}] {Message}", Name, Id, supportCode, context.Name, category, message);

            if (Player is { } player)
            {
                if (_antiCheatConfig.BanIpFromGame)
                {
                    player.Game.BanIp(Connection.EndPoint.Address);
                }

                await player.Game.HandleRemovePlayer(Id, DisconnectReason.Hacking);
            }

            var disconnectMessage =
                $"""
                 You have been caught cheating and were {(_antiCheatConfig.BanIpFromGame ? "banned" : "kicked")} from the lobby.
                 For questions, contact your server admin and share the following code: {supportCode}.
                 """;

            await DisconnectAsync(DisconnectReason.Custom, disconnectMessage);

            return true;
        }

        public override async ValueTask HandleMessageAsync(IMessageReader reader, MessageType messageType)
        {
            await DisconnectAsync(DisconnectReason.Custom, "You are using an abandoned domain to access the server.\nPlease update to latest!\n你在使用一个已经停用的域名访问私服\n请及时更新！\n<nobr><link=\"https://au.niko233.me/\">Update|更新 au.niko233.me</nobr></link>");
            return;
        }

        public override async ValueTask HandleDisconnectAsync(string reason)
        {
            try
            {
                if (Player != null)
                {
                    // The client never sends over the real disconnect reason so we always assume ExitGame
                    var isRemote = reason == "The remote sent a disconnect request";
                    await Player.Game.HandleRemovePlayer(Id, isRemote ? DisconnectReason.ExitGame : DisconnectReason.Error);
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

            // GameCode must match code of the current game assigned to the player.
            if (message.ReadInt32() != game.Code)
            {
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
