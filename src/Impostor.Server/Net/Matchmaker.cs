using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Impostor.Api.Events.Managers;
using Impostor.Api.Net.Messages.C2S;
using Impostor.Hazel;
using Impostor.Hazel.Udp;
using Impostor.Server.Events.Client;
using Impostor.Server.Net.Hazel;
using Impostor.Server.Net.Manager;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Impostor.Server.Net
{
    internal class Matchmaker
    {
        private readonly IEventManager _eventManager;
        private readonly ClientManager _clientManager;
        private readonly ObjectPool<MessageReader> _readerPool;
        private readonly ILogger<HazelConnection> _connectionLogger;
        private readonly List<UdpConnectionListener> _connections = new List<UdpConnectionListener>();
        public static Dictionary<IPEndPoint, IPEndPoint> connections = new Dictionary<IPEndPoint, IPEndPoint>();

        public Matchmaker(
            IEventManager eventManager,
            ClientManager clientManager,
            ObjectPool<MessageReader> readerPool,
            ILogger<HazelConnection> connectionLogger)
        {
            _eventManager = eventManager;
            _clientManager = clientManager;
            _readerPool = readerPool;
            _connectionLogger = connectionLogger;
        }

        public async ValueTask StartAsync(IPEndPoint ipEndPoint)
        {
            var mode = ipEndPoint.AddressFamily switch
            {
                AddressFamily.InterNetwork => IPMode.IPv4,
                AddressFamily.InterNetworkV6 => IPMode.IPv6,
                _ => throw new InvalidOperationException(),
            };

            var initialConnection = new UdpConnectionListener(ipEndPoint, _readerPool, mode);
            initialConnection.NewConnection = (e) => OnNewConnectionAsync(e, initialConnection); // 移出初始化表达式

            await initialConnection.StartAsync();
            _connections.Add(initialConnection);
        }

        public async ValueTask StartNewAsync(IPEndPoint ipEndPoint)
        {
            var mode = ipEndPoint.AddressFamily switch
            {
                AddressFamily.InterNetwork => IPMode.IPv4,
                AddressFamily.InterNetworkV6 => IPMode.IPv6,
                _ => throw new InvalidOperationException(),
            };

            var newConnection = new UdpConnectionListener(ipEndPoint, _readerPool, mode);
            newConnection.NewConnection = (e) => OnNewConnectionAsync(e, newConnection); // 移出初始化表达式

            _connections.Add(newConnection);
            await newConnection.StartAsync();
        }

        public async ValueTask StopAsync()
        {
            foreach (var connection in _connections)
            {
                await connection.DisposeAsync();
            }

            _connections.Clear();
        }

        private async ValueTask OnNewConnectionAsync(NewConnectionEventArgs e, UdpConnectionListener currentListener) // 修改这一行
        {
            // Handshake.
            HandshakeC2S.Deserialize(e.HandshakeData, out var clientVersion, out var name, out var language, out var chatMode, out var platformSpecificData);

            var connection = new HazelConnection(e.Connection, _connectionLogger);

            await _eventManager.CallAsync(new ClientConnectionEvent(connection, e.HandshakeData));

            // Register client
            await _clientManager.RegisterConnectionAsync(connection, name, clientVersion, language, chatMode, platformSpecificData);

            connections.Add(e.Connection.EndPoint, currentListener.EndPoint);
        }
    }
}
