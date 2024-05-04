using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Innersloth;
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

        private static readonly Dictionary<uint, Type> SpawnableObjects = new()
        {
            [0] = typeof(InnerSkeldShipStatus),
            [1] = typeof(InnerMeetingHud),
            [2] = typeof(InnerLobbyBehaviour),
            [3] = typeof(InnerGameData),
            [4] = typeof(InnerPlayerControl),
            [5] = typeof(InnerMiraShipStatus),
            [6] = typeof(InnerPolusShipStatus),
            [7] = typeof(InnerDleksShipStatus),
            [8] = typeof(InnerAirshipStatus),
            [9] = typeof(InnerHideAndSeekManager),
            [10] = typeof(InnerNormalGameManager),
            [13] = typeof(InnerFungleShipStatus),
        };

        private readonly List<InnerNetObject> _allObjects = new List<InnerNetObject>();

        private readonly Dictionary<uint, InnerNetObject> _allObjectsFast = new Dictionary<uint, InnerNetObject>();

        private readonly Dictionary<int, int> _errroVL = new();

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
                    var tag = (GameDataTag)reader.Tag;

                    if (!sender.IsHost && sender.Game.IsHostAuthoritive && tag != GameDataTag.RpcFlag && tag != GameDataTag.DataFlag)
                    {
                        _logger.LogDebug("{0} - Got GameData tag from {1} of type {2}", Code, sender.Client.Name, tag);
                    }

                    switch (tag)
                    {
                        case GameDataTag.DataFlag:
                        {
                            var netId = reader.ReadPackedUInt32();
                            if (_allObjectsFast.TryGetValue(netId, out var obj))
                            {
                                await obj.DeserializeAsync(sender, target, reader, false);
                            }
                            else
                            {
                                _logger.LogWarning("Received DataFlag for unregistered NetId {0} from client {1}.", netId, sender.Client.Id);
                            }

                            break;
                        }

                        case GameDataTag.RpcFlag:
                        {
                            var netId = reader.ReadPackedUInt32();
                            if (_allObjectsFast.TryGetValue(netId, out var obj))
                            {
                                if (!await obj.HandleRpcAsync(sender, target, (RpcCalls)reader.ReadByte(), reader))
                                {
                                    parent.RemoveMessage(reader);
                                    continue;
                                }
                            }
                            else
                            {
                                _logger.LogWarning("Received RpcFlag for unregistered NetId {0} from client {1}.", netId, sender.Client.Id);
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

                            if (scene == string.Empty || scene == null)
                            {
                                _logger.LogWarning("Player {0} ({1}) tried to send SceneChangeFlag with null scene. Kicking.", sender.Client.Name, sender.Client.Id);
                                await sender.Client.DisconnectAsync(DisconnectReason.Error);
                                return false;
                            }

                            if (clientId != sender.Client.Id)
                            {
                                _logger.LogWarning(
                                    "Player {0} ({1}) tried to send SceneChangeFlag for another player.",
                                    sender.Client.Name,
                                    sender.Client.Id);

                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SceneChangeFlag)), CheatCategory.Ownership, "Tried to send SceneChangeFlag as other player."))
                                {
                                    return false;
                                }

                                return false;
                            }

                            if (scene.ToLower() == "tutorial")
                            {
                                _logger.LogWarning("Player {0} ({1}) tried to change scene to tutorial. Kicking.", sender.Client.Name, sender.Client.Id);

                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SceneChangeFlag)), CheatCategory.Other, "Tried to change scene to tutorial."))
                                {
                                    return false;
                                }

                                return false;
                            }

                            sender.Scene = scene;

                            _logger.LogTrace("> Scene {0} to {1}", clientId, sender.Scene);
                            break;
                        }

                        case GameDataTag.ReadyFlag:
                        {
                            var clientId = reader.ReadPackedInt32();

                            if (clientId != sender.Client.Id)
                            {
                                if (await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.ReadyFlag)), CheatCategory.Ownership, "Client sent info with wrong client id"))
                                {
                                    return false;
                                }
                            }

                            if (GameState != GameStates.Starting)
                            {
                                _logger.LogWarning("{0} - Player {1} ({2}) tried to send ReadyFlag but game is not starting.", Code, sender.Client.Name, sender.Client.Id);

                                if (clientId != HostId)
                                {
                                    return false;
                                }
                            }

                            _logger.LogTrace("{0} -> IsReady {1}", Code, clientId);
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

                return true;
            }
            catch
            {
                _logger.LogError("{0} - get GameData/GameDataTo that failed to handle from {0}({1})", Code, sender.Client.Name, sender.Client.Id);

                if (_errroVL.TryGetValue(sender.Client.Id, out var vl))
                {
                    _errroVL[sender.Client.Id] = ++vl;
                    if (sender.Client.Id == HostId)
                    {
                        if (vl >= 12)
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

                    _logger.LogWarning("Curret GameData vl : {0}", _errroVL[sender.Client.Id]);
                }
                else
                {
                    _errroVL.TryAdd(sender.Client.Id, 1);
                    _logger.LogWarning("Curret GameData vl : {0}", _errroVL[sender.Client.Id]);
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

                case InnerGameData data:
                {
                    GameNet.GameData = data;
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
                        break;
                    }

                    // Hook up InnerPlayerControl <-> InnerPlayerControl.PlayerInfo.
                    var playerInfo = GameNet.GameData!.GetPlayerById(control.PlayerId) ?? GameNet.GameData.AddPlayer(control);

                    if (playerInfo != null)
                    {
                        playerInfo.Controller = control;
                        control.PlayerInfo = playerInfo;
                    }

                    if (player != null)
                    {
                        _logger.LogInformation("{0} - Player {1} ({2}) spawned as {3} by {4}, hashpuid is {5}", Code, player!.Client.Name, player!.Client.Id, control.PlayerId, sender.Client.Id, player!.Client.HashedPuid());
                        await _eventManager.CallAsync(new PlayerSpawnedEvent(this, player, control));
                    }

                    if (player == null)
                    {
                        _logger.LogWarning("{0} - PlayerControl {1} ({2}) spawned by {3}, but target client is null!", Code, control.PlayerId, control.OwnerId, sender.Client.Id);
                    }

                    break;
                }

                case InnerCustomNetworkTransform:
                case InnerPlayerPhysics:
                    break;

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

                default:
                {
                    _logger.LogWarning("{0} - Spawned a Net object that server doesnt recoginze. {1} for {2} by {3}", Code, netObj.NetId, netObj.OwnerId, sender.Client.Id);

                    // await sender.Client.ReportCheatAsync(new CheatContext(nameof(GameDataTag.SpawnFlag)), CheatCategory.ProtocolExtension, "Spawned a Net object that server doesnt recoginze.");
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

                case InnerGameData:
                {
                    GameNet.GameData = null;
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

                case InnerPlayerControl control:
                {
                    if (GameState != GameStates.Started && GameState != GameStates.Starting)
                    {
                        GameNet.GameData?.RemovePlayer(control);
                    }

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
