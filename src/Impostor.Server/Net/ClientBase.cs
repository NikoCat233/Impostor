using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Impostor.Api;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Server.Net.State;

namespace Impostor.Server.Net
{
    internal abstract class ClientBase : IClient
    {
        protected ClientBase(string name, GameVersion gameVersion, Language language, QuickChatModes chatMode, PlatformSpecificData platformSpecificData, IHazelConnection connection)
        {
            Name = name;
            GameVersion = gameVersion;
            Language = language;
            ChatMode = chatMode;
            PlatformSpecificData = platformSpecificData;
            Connection = connection;
            Items = new ConcurrentDictionary<object, object>();
        }

        public int Id { get; set; }

        public string Name { get; }

        public string Puid { get; set; }

        public Language Language { get; }

        public QuickChatModes ChatMode { get; }

        public PlatformSpecificData PlatformSpecificData { get; }

        public GameVersion GameVersion { get; }

        public IHazelConnection Connection { get; }

        public IDictionary<object, object> Items { get; }

        public ClientPlayer? Player { get; set; }

        IClientPlayer? IClient.Player => Player;

        public virtual ValueTask<bool> ReportCheatAsync(CheatContext context, CheatCategory category, string message)
        {
            return new ValueTask<bool>(false);
        }

        public ValueTask<bool> ReportCheatAsync(CheatContext context, string message)
        {
            return ReportCheatAsync(context, CheatCategory.Other, message);
        }

        public abstract ValueTask HandleMessageAsync(IMessageReader message, MessageType messageType);

        public abstract ValueTask HandleDisconnectAsync(string reason);

        public async ValueTask DisconnectAsync(DisconnectReason reason, string? message = null)
        {
            await Connection.CustomDisconnectAsync(reason, message);
        }

        public string HashedPuid()
        {
            if (Puid == null || Puid == string.Empty)
            {
                return string.Empty;
            }

            var puid = Puid;

            var sha256Bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(puid));
            var sha256Hash = BitConverter.ToString(sha256Bytes).Replace("-", string.Empty).ToLower();

            return string.Concat(sha256Hash.AsSpan(0, 5), sha256Hash.AsSpan(sha256Hash.Length - 4));
        }
    }
}
