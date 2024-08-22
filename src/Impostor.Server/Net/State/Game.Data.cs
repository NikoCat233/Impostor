using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Api.Net.Inner;
using Impostor.Api.Unity;
using Impostor.Server.Events.Meeting;
using Impostor.Server.Events.Player;
using Impostor.Server.Net.Inner;
using Impostor.Server.Net.Inner.Objects;
using Impostor.Server.Net.Inner.Objects.Components;
using Impostor.Server.Net.Inner.Objects.GameManager;
using Impostor.Server.Net.Inner.Objects.ShipStatus;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Impostor.Server.Net.State
{
    internal partial class Game
    {
        /// <summary>
        ///     Used for global object, spawned by the host.
        /// </summary>
        private const int InvalidClient = -2;

        /// <summary>
        ///     Used internally to set the OwnerId to the current ClientId.
        ///     i.e: <code>ownerId = ownerId == -3 ? this.ClientId : ownerId;</code>
        /// </summary>
        private const int CurrentClient = -3;

        /// <summary>
        ///     Used to list objects that are managed by the game server.
        /// </summary>
        private const int ServerOwned = -4;

        /// <summary>
        ///     The first NetId that is considered as a server owned Network ID that the client will not allocate by default.
        /// </summary>
        private const int MinServerNetId = 100000;

        private static readonly Dictionary<uint, Type> SpawnableObjects = new()
        {
            [0] = typeof(InnerSkeldShipStatus),
            [1] = typeof(InnerMeetingHud),
            [2] = typeof(InnerLobbyBehaviour),
            [4] = typeof(InnerPlayerControl),
            [5] = typeof(InnerMiraShipStatus),
            [6] = typeof(InnerPolusShipStatus),
            [7] = typeof(InnerDleksShipStatus),
            [8] = typeof(InnerAirshipStatus),
            [9] = typeof(InnerHideAndSeekManager),
            [10] = typeof(InnerNormalGameManager),
            [11] = typeof(InnerPlayerInfo),
            [12] = typeof(InnerVoteBanSystem),
            [13] = typeof(InnerFungleShipStatus),
        };

        private static readonly Dictionary<Type, uint> SpawnableObjectIds = SpawnableObjects.ToDictionary((i) => i.Value, (i) => i.Key);

        private readonly List<InnerNetObject> _allObjects = new List<InnerNetObject>();

        private readonly Dictionary<uint, InnerNetObject> _allObjectsFast = new Dictionary<uint, InnerNetObject>();

        private readonly Dictionary<int, int> _errorVL = new();

        private uint _nextNetId = MinServerNetId;

        public T? FindObjectByNetId<T>(uint netId)
            where T : IInnerNetObject
        {
            if (_allObjectsFast.TryGetValue(netId, out var obj))
            {
                return (T)(IInnerNetObject)obj;
            }

            return default;
        }

        public async ValueTask<bool> HandleGameDataAsync(IMessageReader parent, ClientPlayer sender, bool toPlayer)
        {
            try
            {
                // Find target player.
                ClientPlayer? target = null;

                if (toPlayer)
                {
                    var targetId = parent.ReadPackedInt32();
                    if (!TryGetPlayer(targetId, out target))
                    {
                        _logger.LogWarning("Player {0} tried to send GameData to unknown player {1}.", sender.Client.Id, targetId);
                        return false;
                    }

                    _logger.LogTrace("Received GameData for target {0}.", targetId);
                }

                // Parse GameData messages.
                while (parent.Position < parent.Length)
                {
                    using var reader = parent.ReadMessage();

                    var position = reader.Position;
                    _logger.LogTrace("Client {SenderId} sent GameData {Tag}", sender.Client.Id, (GameDataTag)reader.Tag);

                    switch ((GameDataTag)reader.Tag)
                    {
                        case GameDataTag.DataFlag:
                        {
                            var netId = reader.ReadPackedUInt32();
                            if (_allObjectsFast.TryGetValue(netId, out var obj))
                            {
                                _logger.LogTrace("Received Data for {NetId}, which is of type {Type}", netId, obj.GetType().Name);
                                await obj.DeserializeAsync(sender, target, reader, false);

                                if (obj.OwnerId == -2 && obj is InnerPlayerInfo)
                                {
                                    reader.Seek(position);

                                    using var writer = StartGameData(toPlayer ? target!.Client.Id : null, MessageType.Unreliable);
                                    reader.CopyTo(writer);
                                    writer.EndMessage();

                                    if (toPlayer)
                                    {
                                        await SendToAsync(writer, target!.Client.Id);
                                    }
                                    else
                                    {
                                        await SendToAllExceptAsync(writer, sender.Client.Id);
                                    }

                                    parent.RemoveMessage(reader);
                                    break;
                                }
                            }
                            else
                            {
                                _logger.LogWarning("Received DataFlag for unregistered NetId {0}.", netId);
                            }

                            break;
                        }

                        case GameDataTag.RpcFlag:
                        {
                            var netId = reader.ReadPackedUInt32();
                            if (_allObjectsFast.TryGetValue(netId, out var obj))
                            {
                                var call = (RpcCalls)reader.ReadByte();
                                _logger.LogTrace(
                                    "Client {SenderId} called Rpc {Call} on NetId {CallerId} and sent it to {Target}",
                                    sender.Client.Id,
                                    call,
                                    obj.NetId,
                                    target?.Client.Id.ToString() ?? "everyone");

                                if (!await obj.HandleRpcAsync(sender, target, call, reader))
                                {
                                    parent.RemoveMessage(reader);
                                    continue;
                                }

                                if (reader.Length > 200) // Normally a rpc should be within 100. gonna send it as none so wont cause huge packets.
                                {
                                    reader.Seek(position);

                                    using var writer = StartGameData(toPlayer ? target!.Client.Id : null, MessageType.Unreliable);
                                    reader.CopyTo(writer);
                                    writer.EndMessage();

                                    if (toPlayer)
                                    {
                                        await SendToAsync(writer, target!.Client.Id);
                                    }
                                    else
                                    {
                                        await SendToAllExceptAsync(writer, sender.Client.Id);
                                    }

                                    parent.RemoveMessage(reader);
                                    continue;
                                }
                            }
                            else
                            {
                                _logger.LogWarning("{0} - Received RpcFlag for unregistered NetId {1} from {2}", Code, netId, sender.Client.Id);
                            }

                            break;
                        }

                        case GameDataTag.SpawnFlag:
                        {
                            // Only the host is allowed to spawn objects.
                            if (!sender.IsHost)
                            {
                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SpawnFlag)), CheatCategory.MustBeHost, "Tried to send SpawnFlag as non-host."))
                                {
                                    return false;
                                }
                            }

                            var objectId = reader.ReadPackedUInt32();
                            if (SpawnableObjects.TryGetValue(objectId, out var spawnableObjectType))
                            {
                                var innerNetObject = (InnerNetObject)ActivatorUtilities.CreateInstance(_serviceProvider, spawnableObjectType, this);
                                var ownerClientId = reader.ReadPackedInt32();

                                innerNetObject.SpawnFlags = (SpawnFlags)reader.ReadByte();

                                var components = innerNetObject.GetComponentsInChildren<InnerNetObject>();
                                var componentsCount = reader.ReadPackedInt32();

                                if (componentsCount != components.Count)
                                {
                                    _logger.LogError(
                                        "Children didn't match for spawnable {0}, name {1} ({2} != {3})",
                                        objectId,
                                        innerNetObject.GetType().Name,
                                        componentsCount,
                                        components.Count);
                                    continue;
                                }

                                _logger.LogDebug(
                                    "Spawning {0} components, SpawnFlags {1}",
                                    innerNetObject.GetType().Name,
                                    innerNetObject.SpawnFlags);

                                for (var i = 0; i < componentsCount; i++)
                                {
                                    var obj = components[i];

                                    obj.NetId = reader.ReadPackedUInt32();
                                    obj.OwnerId = ownerClientId;

                                    _logger.LogDebug(
                                        "- {0}, NetId {1}, OwnerId {2}",
                                        obj.GetType().Name,
                                        obj.NetId,
                                        obj.OwnerId);

                                    if (!AddNetObject(obj))
                                    {
                                        _logger.LogTrace("Failed to AddNetObject, it already exists.");

                                        obj.NetId = uint.MaxValue;
                                        break;
                                    }

                                    using var readerSub = reader.ReadMessage();
                                    if (readerSub.Length > 0)
                                    {
                                        await obj.DeserializeAsync(sender, target, readerSub, true);
                                    }

                                    await OnSpawnAsync(sender, obj);
                                }

                                if (toPlayer)
                                {
                                    if (objectId == 11)
                                    {
                                        reader.Seek(position);

                                        using var writer = StartGameData(target!.Client.Id);
                                        reader.CopyTo(writer);
                                        writer.EndMessage();
                                        await SendToAsync(writer, target!.Client.Id);

                                        parent.RemoveMessage(reader);
                                        continue;
                                    }
                                }

                                continue;
                            }

                            _logger.LogWarning("Couldn't find spawnable object {0}.", objectId);
                            break;
                        }

                        // Only the host is allowed to despawn objects.
                        case GameDataTag.DespawnFlag:
                        {
                            var netId = reader.ReadPackedUInt32();
                            if (_allObjectsFast.TryGetValue(netId, out var obj))
                            {
                                if (sender.Client.Id != obj.OwnerId && !sender.IsHost)
                                {
                                    _logger.LogWarning(
                                        "Player {0} ({1}) tried to send DespawnFlag for {2} but was denied.",
                                        sender.Client.Name,
                                        sender.Client.Id,
                                        netId);
                                    return false;
                                }

                                if (sender.Client.Id == obj.OwnerId && !sender.IsHost)
                                {
                                    if (sender.Limbo == LimboStates.NotLimbo && GameState != GameStates.Ended)
                                    {
                                        _logger.LogWarning(
                                            "Player {0} ({1}) tried to send DespawnFlag for {2} owned by itself after joined.",
                                            sender.Client.Name,
                                            sender.Client.Id,
                                            netId);

                                        if (obj is InnerPlayerControl)
                                        {
                                            _logger.LogWarning("Player {0} ({1}) tried to despawn itself PlayerControl. Issue a kick", sender.Client.Name, sender.Client.Id);
                                            if (sender.Client.Connection.IsConnected)
                                            {
                                                await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.DespawnFlag)), CheatCategory.ForSure, "Client Despawning its own player control");
                                            }
                                        }
                                    }
                                }

                                RemoveNetObject(obj);
                                await OnDestroyAsync(obj);
                                _logger.LogDebug("Destroyed InnerNetObject {0} ({1}), OwnerId {2}", obj.GetType().Name, netId, obj.OwnerId);
                            }
                            else
                            {
                                _logger.LogDebug(
                                    "Player {0} ({1}) sent DespawnFlag for unregistered NetId {2}.",
                                    sender.Client.Name,
                                    sender.Client.Id,
                                    netId);
                            }

                            break;
                        }

                        case GameDataTag.SceneChangeFlag:
                        {
                            // Sender is only allowed to change his own scene.
                            var clientId = reader.ReadPackedInt32();
                            var scene = reader.ReadString();

                            if (clientId != sender.Client.Id)
                            {
                                _logger.LogWarning(
                                    "Player {0} ({1}) tried to send SceneChangeFlag for another player.",
                                    sender.Client.Name,
                                    sender.Client.Id);

                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SceneChangeFlag)), CheatCategory.ForSure, "Client tried to change scene for another player"))
                                {
                                    return false;
                                }

                                return false;
                            }

                            // According to game assembly, sender is only allowed to send OnlineGame.
                            if (scene != "OnlineGame")
                            {
                                _logger.LogWarning(
                                    "Player {0} ({1}) tried to send SceneChangeFlag with disallowed scene.",
                                    sender.Client.Name,
                                    sender.Client.Id);

                                if (scene.ToLower() == "tutorial" && await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SceneChangeFlag)), CheatCategory.ForSure, "Client tried to change scene to Tutorial"))
                                {
                                    return false;
                                }

                                return false;
                            }
                            else
                            {
                                if (GameState == GameStates.Started)
                                {
                                    _logger.LogWarning("Player {0} ({1}) tried to change scene to onlinegame while game is running.", sender.Client.Name, sender.Client.Id);
                                    return false;
                                }

                                if (!_sentOnlineGameClients.Contains(sender.Client.Id))
                                {
                                    _sentOnlineGameClients.Add(sender.Client.Id);
                                }
                                else
                                {
                                    _logger.LogWarning(
                                        "Player {0} ({1}) tried to send Online game again.",
                                        sender.Client.Name,
                                        sender.Client.Id);
                                    return false;
                                }
                            }

                            sender.Scene = scene;

                            _logger.LogTrace("> Scene {0} to {1}", clientId, sender.Scene);

                            await SyncServerObjectsAsync(sender);
                            await SpawnPlayerInfoAsync(sender);

                            break;
                        }

                        case GameDataTag.ReadyFlag:
                        {
                            var clientId = reader.ReadPackedInt32();

                            if (clientId != sender.Client.Id)
                            {
                                _logger.LogWarning(
                                    "Player {0} ({1}) tried to send ReadyFlag for another player.",
                                    sender.Client.Name,
                                    sender.Client.Id);
                                return false;
                            }

                            if (GameState != GameStates.Starting)
                            {
                                if (clientId != HostId)
                                {
                                    _logger.LogWarning("{0} - Player {1} ({2}) tried to send ReadyFlag but game is not starting.", Code, sender.Client.Name, sender.Client.Id);
                                    return false;
                                }
                            }

                            _logger.LogTrace("> IsReady {0}", clientId);
                            break;
                        }

                        case GameDataTag.ConsoleDeclareClientPlatformFlag:
                        {
                            var clientId = reader.ReadPackedInt32();
                            var platform = (RuntimePlatform)reader.ReadPackedInt32();

                            if (clientId != sender.Client.Id)
                            {
                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.ConsoleDeclareClientPlatformFlag)), CheatCategory.Ownership, "Client sent info with wrong client id"))
                                {
                                    return false;
                                }
                            }

                            sender.Platform = platform;

                            break;
                        }

                        default:
                        {
                            _logger.LogWarning("Bad GameData tag {0}", reader.Tag);
                            break;
                        }
                    }

                    if (sender.Client.Player == null)
                    {
                        // Disconnect handler was probably invoked, cancel the rest.
                        return false;
                    }
                }

                // Check for dirty netobjects
                foreach (var netObject in _allObjectsFast.Values)
                {
                    if (netObject.IsDirty && netObject.OwnerId == ServerOwned)
                    {
                        _logger.LogTrace("Sending over {Type} {NetId}", netObject.GetType().Name, netObject.NetId);
                        await SendObjectData(netObject);
                        netObject.IsDirty = false;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling GameData");
                _logger.LogError("{0} - get GameData/GameDataTo that failed to handle from {0}({1})", Code, sender.Client.Name, sender.Client.Id);

                if (_errorVL.TryGetValue(sender.Client.Id, out var vl))
                {
                    _errorVL[sender.Client.Id] = ++vl;
                    if (sender.Client.Id == HostId)
                    {
                        if (vl >= 9)
                        {
                            await sender.RemoveAsync(DisconnectReason.Custom, "Server failed to handle your packet (GameData Host).\nThis maybe a server-side bug.\nSorry for any inconvenience caused.\nReport issues at <nobr><link=\"https://discord.gg/tohe\">dsc.gg/tohe</nobr></link>");
                        }
                    }
                    else
                    {
                        if (vl >= 3)
                        {
                            await sender.RemoveAsync(DisconnectReason.Custom, "Server failed to handle your packet (GameData).\nThis maybe a server-side bug.\nSorry for any inconvenience caused.\nReport issues at <nobr><link=\"https://discord.gg/tohe\">dsc.gg/tohe</nobr></link>");
                        }
                    }

                    _logger.LogWarning("Curret GameData vl : {0}", _errorVL[sender.Client.Id]);
                }
                else
                {
                    _errorVL.TryAdd(sender.Client.Id, 1);
                    _logger.LogWarning("Curret GameData vl : {0}", _errorVL[sender.Client.Id]);
                }

                return false;
            }
        }

        private async ValueTask OnSpawnAsync(ClientPlayer sender, InnerNetObject netObj)
        {
            switch (netObj)
            {
                case InnerGameManager innerGameManager:
                {
                    GameNet.GameManager = innerGameManager;
                    break;
                }

                case InnerLobbyBehaviour lobby:
                {
                    GameNet.LobbyBehaviour = lobby;
                    break;
                }

                case InnerPlayerInfo playerInfo:
                {
                    if (!GameNet.GameData.AddPlayer(playerInfo))
                    {
                        _logger.LogWarning(
                            "Could not add PlayerInfo for playerId {PlayerId} with NetId {newId}, already have NetId {oldNetId}",
                            playerInfo.PlayerId,
                            playerInfo.NetId,
                            GameNet.GameData.GetPlayerById(playerInfo.PlayerId)?.NetId);
                    }

                    break;
                }

                case InnerVoteBanSystem voteBan:
                {
                    GameNet.VoteBan = voteBan;
                    break;
                }

                case InnerShipStatus shipStatus:
                {
                    GameNet.ShipStatus = shipStatus;
                    break;
                }

                case InnerPlayerControl control:
                {
                    // Hook up InnerPlayerControl <-> IClientPlayer.
                    if (TryGetPlayer(control.OwnerId, out var player))
                    {
                        player.Character = control;
                        player.DisableSpawnTimeout();
                    }
                    else
                    {
                        await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SpawnFlag)), CheatCategory.GameFlow, "Failed to find player that spawned the InnerPlayerControl");
                    }

                    // Hook up InnerPlayerControl <-> InnerPlayerControl.PlayerInfo.
                    var playerInfo = GameNet.GameData.GetPlayerById(control.PlayerId);

                    if (playerInfo != null)
                    {
                        playerInfo.Controller = control;
                        control.PlayerInfo = playerInfo;

                        // Reset PlayerInfo
                        playerInfo.RoleType = null;
                        playerInfo.RoleWhenAlive = null;
                        playerInfo.Tasks.Clear();
                        playerInfo.IsDead = false;
                        playerInfo.IsDirty = true;
                    }

                    if (player != null)
                    {
                        await _eventManager.CallAsync(new PlayerSpawnedEvent(this, player, control));
                    }

                    break;
                }

                case InnerMeetingHud meetingHud:
                {
                    foreach (var player in _players.Values)
                    {
                        if (GameNet.ShipStatus != null)
                        {
                            await player.Character!.NetworkTransform.SetPositionAsync(player, GameNet.ShipStatus.GetSpawnLocation(player.Character, PlayerCount, false));
                        }
                    }

                    await _eventManager.CallAsync(new MeetingStartedEvent(this, meetingHud));
                    break;
                }
            }

            await netObj.OnSpawnAsync();
        }

        private async ValueTask OnDestroyAsync(InnerNetObject netObj)
        {
            switch (netObj)
            {
                case InnerLobbyBehaviour:
                {
                    GameNet.LobbyBehaviour = null;
                    break;
                }

                case InnerVoteBanSystem:
                {
                    GameNet.VoteBan = null;
                    break;
                }

                case InnerShipStatus:
                {
                    GameNet.ShipStatus = null;
                    break;
                }

                case InnerPlayerInfo playerInfo:
                {
                    if (GameState != GameStates.Started && GameState != GameStates.Starting)
                    {
                        GameNet.GameData.RemovePlayer(playerInfo.PlayerId);
                    }

                    break;
                }

                case InnerPlayerControl control:
                {
                    // Remove InnerPlayerControl <-> IClientPlayer.
                    if (TryGetPlayer(control.OwnerId, out var player))
                    {
                        player.Character = null;
                        await _eventManager.CallAsync(new PlayerDestroyedEvent(this, player, control));
                    }

                    break;
                }
            }
        }

        private async ValueTask SyncServerObjectsAsync(ClientPlayer sender)
        {
            foreach (var obj in _allObjectsFast.Values)
            {
                if (obj.OwnerId == ServerOwned)
                {
                    _logger.LogTrace("Syncing {Type} {NetId}", obj.GetType(), obj.NetId);
                    await SendObjectSpawnAsync(obj, sender.Client.Id);
                }
            }
        }

        private async ValueTask SpawnPlayerInfoAsync(ClientPlayer sender)
        {
            // Hosts spawn PlayerInfo objects if they requested authority
            if (IsHostAuthoritive)
            {
                return;
            }

            // Only spawn a new PlayerInfo if one has not yet been spawned
            if (GameNet.GameData.PlayersByClientId.ContainsKey(sender.Client.Id))
            {
                return;
            }

            var playerInfo = (InnerPlayerInfo)ActivatorUtilities.CreateInstance(_serviceProvider, typeof(InnerPlayerInfo), this);
            playerInfo.SpawnFlags = SpawnFlags.None;
            playerInfo.NetId = _nextNetId++;
            playerInfo.OwnerId = ServerOwned;
            playerInfo.ClientId = sender.Client.Id;
            playerInfo.PlayerId = GameNet.GameData.GetNextAvailablePlayerId();

            if (!AddNetObject(playerInfo))
            {
                _logger.LogError("Couldn't spawn PlayerInfo for {Name} ({ClientId})", sender.Client.Name, sender.Client.Id);
                playerInfo.NetId = uint.MaxValue;
                return;
            }

            _logger.LogTrace("Spawning PlayerInfo (netId {Netid})", playerInfo.NetId);
            await OnSpawnAsync(sender, playerInfo);
            await SendObjectSpawnAsync(playerInfo);
        }

        private async ValueTask DespawnPlayerInfoAsync(InnerPlayerInfo playerInfo)
        {
            if (playerInfo.OwnerId == ServerOwned)
            {
                _logger.LogDebug("Despawning PlayerInfo {nid}", playerInfo.NetId);
                GameNet.GameData.RemovePlayer(playerInfo.PlayerId);
                RemoveNetObject(playerInfo);

                await SendObjectDespawnAsync(playerInfo);
            }
        }

        private bool AddNetObject(InnerNetObject obj)
        {
            if (_allObjectsFast.ContainsKey(obj.NetId))
            {
                return false;
            }

            _allObjects.Add(obj);
            _allObjectsFast.Add(obj.NetId, obj);
            return true;
        }

        private void RemoveNetObject(InnerNetObject obj)
        {
            var index = _allObjects.IndexOf(obj);
            if (index > -1)
            {
                _allObjects.RemoveAt(index);
            }

            _allObjectsFast.Remove(obj.NetId);
        }
    }
}
