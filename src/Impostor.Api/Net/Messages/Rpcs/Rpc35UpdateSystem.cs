using Impostor.Api.Games;
using Impostor.Api.Innersloth;
using Impostor.Api.Net.Inner.Objects;

namespace Impostor.Api.Net.Messages.Rpcs
{
    public static class Rpc35UpdateSystem
    {
        public static void Serialize(IMessageWriter writer, SystemTypes systemType, IInnerPlayerControl playerControl, byte amount)
        {
            writer.Write((byte)systemType);
            writer.Write(playerControl);
            writer.Write((byte)amount);
        }

        public static void Deserialize(IMessageReader reader, IGame game, out SystemTypes systemType, out IInnerPlayerControl? playerControl, out byte amount)
        {
            systemType = (SystemTypes)reader.ReadByte();
            playerControl = reader.ReadNetObject<IInnerPlayerControl>(game);

            if (systemType == SystemTypes.Ventilation)
            {
                amount = 0;
                return;
            }

            amount = reader.ReadByte();
        }
    }
}
