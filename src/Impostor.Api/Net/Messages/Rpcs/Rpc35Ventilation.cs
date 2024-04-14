using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net.Inner.Objects;

namespace Impostor.Api.Net.Messages.Rpcs
{
    public static class Rpc35Ventilation
    {
        public static void Serialize(IMessageWriter writer, SystemTypes systemType, IInnerPlayerControl playerControl, ushort sequenceId, byte state, byte ventId)
        {
            // Should always write SystemTypes.Ventilation
            writer.Write((byte)systemType);
            writer.Write(playerControl);
            writer.Write(sequenceId);
            writer.Write(state);
            writer.Write(ventId);
        }

        public static void Deserialize(IMessageReader reader, IGame game, out SystemTypes systemType, out IInnerPlayerControl? playerControl, out ushort sequenceId, out byte state, out byte ventId)
        {
            // Not finished
            systemType = (SystemTypes)reader.ReadByte();
            playerControl = reader.ReadNetObject<IInnerPlayerControl>(game);
            sequenceId = reader.ReadUInt16();
            state = reader.ReadByte();
            ventId = reader.ReadByte();
        }
    }
}
