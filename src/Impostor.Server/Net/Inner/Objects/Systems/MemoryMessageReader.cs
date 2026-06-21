using System;
using System.Buffers.Binary;
using System.Text;

namespace Impostor.Server.Net.Inner.Objects.Systems
{
    internal sealed class MemoryMessageReader : IMessageReader
    {
        public MemoryMessageReader(ReadOnlyMemory<byte> buffer, byte tag = byte.MaxValue)
        {
            Buffer = buffer.ToArray();
            Length = Buffer.Length;
            Tag = tag;
        }

        public byte Tag { get; }

        public byte[] Buffer { get; }

        public int Offset => 0;

        public int Position { get; private set; }

        public int Length { get; }

        public void Dispose()
        {
        }

        public IMessageReader ReadMessage()
        {
            var length = ReadUInt16();
            var tag = ReadByte();
            var message = new MemoryMessageReader(Buffer.AsMemory(Position, length), tag);
            Position += length;
            return message;
        }

        public bool ReadBoolean() => ReadByte() != 0;

        public sbyte ReadSByte() => unchecked((sbyte)ReadByte());

        public byte ReadByte()
        {
            return Buffer[Position++];
        }

        public ushort ReadUInt16()
        {
            var value = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(ushort);
            return value;
        }

        public short ReadInt16()
        {
            var value = BinaryPrimitives.ReadInt16LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(short);
            return value;
        }

        public uint ReadUInt32()
        {
            var value = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(uint);
            return value;
        }

        public int ReadInt32()
        {
            var value = BinaryPrimitives.ReadInt32LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(int);
            return value;
        }

        public ulong ReadUInt64()
        {
            var value = BinaryPrimitives.ReadUInt64LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(ulong);
            return value;
        }

        public long ReadInt64()
        {
            var value = BinaryPrimitives.ReadInt64LittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(long);
            return value;
        }

        public float ReadSingle()
        {
            var value = BinaryPrimitives.ReadSingleLittleEndian(Buffer.AsSpan(Position));
            Position += sizeof(float);
            return value;
        }

        public string ReadString(int length)
        {
            var value = Encoding.UTF8.GetString(Buffer.AsSpan(Position, length));
            Position += length;
            return value;
        }

        public string ReadString()
        {
            return ReadString(ReadPackedInt32());
        }

        public ReadOnlyMemory<byte> ReadBytesAndSize()
        {
            return ReadBytes(ReadPackedInt32());
        }

        public ReadOnlyMemory<byte> ReadBytes(int length)
        {
            var value = Buffer.AsMemory(Position, length);
            Position += length;
            return value;
        }

        public int ReadPackedInt32() => (int)ReadPackedUInt32();

        public uint ReadPackedUInt32()
        {
            var result = 0u;
            var shift = 0;

            while (true)
            {
                var b = ReadByte();
                result |= (uint)(b & 0x7f) << shift;

                if ((b & 0x80) == 0)
                {
                    return result;
                }

                shift += 7;
            }
        }

        public void CopyTo(IMessageWriter writer)
        {
            writer.Write((ushort)Length);
            writer.Write(Tag);
            writer.Write(Buffer.AsMemory(0, Length));
        }

        public void Seek(int position)
        {
            Position = position;
        }

        public void RemoveMessage(IMessageReader message)
        {
            throw new NotSupportedException();
        }

        public IMessageReader Copy(int offset = 0)
        {
            return new MemoryMessageReader(Buffer.AsMemory(offset, Length - offset), Tag);
        }
    }
}
