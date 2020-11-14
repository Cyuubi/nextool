using CyuNEX.Utilities;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CyuNEX.PRUDP
{
    class V0_Packet
    {
        private string _accessKey;

        public StreamType SourceType;
        public byte Source;

        public StreamType DestinationType;
        public byte Destination;

        public V0_Flags Flags;
        public V0_Type Type;

        public byte SessionId;
        public ushort SequenceId;

        public uint ConnectionSignature;
        public byte FragmentId;

        public byte[] Payload;

        public V0_Packet(string accessKey)
        {
            _accessKey = accessKey;
        }

        public byte[] CreateRaw()
        {
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                // TODO: HACK! Should not always be RVSecure!
                writer.Write((byte)((byte)SourceType << 4 | Source));
                writer.Write((byte)((byte)DestinationType << 4 | Destination));

                writer.Write((ushort)((ushort)Flags << 4 | (byte)Type));

                writer.Write(SessionId);
                writer.Write(GetPacketSignature());
                writer.Write(SequenceId);

                if (Type == V0_Type.SYN || Type == V0_Type.CONNECT)
                    writer.Write(ConnectionSignature);
                else if (Type == V0_Type.DATA)
                    writer.Write(FragmentId);

                if (Flags.HasFlag(V0_Flags.FLAG_HAS_SIZE))
                    writer.Write(Payload.Length);

                if (Payload.Length > 0)
                    writer.Write(Payload);

                writer.Write(Checksum(stream.ToArray()));

                return stream.ToArray();
            }
        }

        public void ParseRaw(byte[] buffer)
        {
            using (MemoryStream stream = new MemoryStream(buffer))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                byte src = reader.ReadByte();
                byte dst = reader.ReadByte();

                SourceType = (StreamType)((src >> 4) & 0xF);
                Source = (byte)(src & 0xF);
                DestinationType = (StreamType)((dst >> 4) & 0xF);
                Destination = (byte)(dst & 0xF);

                ushort flagsType = reader.ReadUInt16();

                Flags = (V0_Flags)(flagsType >> 4);
                Type = (V0_Type)(flagsType & 0xF);

                SessionId = reader.ReadByte();
                uint packetSignature = reader.ReadUInt32();
                SequenceId = reader.ReadUInt16();

                if (Type == V0_Type.SYN || Type == V0_Type.CONNECT)
                    ConnectionSignature = reader.ReadUInt32();
                else if (Type == V0_Type.DATA)
                    FragmentId = reader.ReadByte();

                var payloadSize = 0;
                if (Flags.HasFlag(V0_Flags.FLAG_HAS_SIZE))
                    payloadSize = reader.ReadUInt16();
                else
                    payloadSize = (ushort)(buffer.Length - stream.Position - 1);

                if (payloadSize > 0)
                    Payload = reader.ReadBytes(payloadSize);
                else
                    Payload = new byte[payloadSize];

                byte checksum = reader.ReadByte();

                Console.WriteLine($"Source               = {Source}");
                Console.WriteLine($"Destination          = {Destination}");
                Console.WriteLine($"Flags                = {Flags}");
                Console.WriteLine($"Type                 = {Type}");
                Console.WriteLine($"Session ID           = {SessionId}");
                Console.WriteLine($"Packet Signature     = 0x{packetSignature:X8}");
                Console.WriteLine($"Sequence ID          = {SequenceId}");
                Console.WriteLine($"Connection Signature = 0x{ConnectionSignature:X8}");
                Console.WriteLine($"Fragment ID          = {FragmentId}");
                Console.WriteLine($"Payload Size         = {Payload.Length}");
                Console.WriteLine($"Checksum             = 0x{checksum:X2}\n");
            }
        }

        // TODO: Only works for friends!
        private uint GetPacketSignature()
        {
            if (Type == V0_Type.DATA && Payload.Length == 0)
                return 0x12345678;
            else if (Type == V0_Type.DATA)
            {
                using (MD5 md5 = MD5.Create())
                using (HMAC hmac = new HMACMD5(md5.ComputeHash(Encoding.ASCII.GetBytes(_accessKey))))
                {
                    return BitConverter.ToUInt32(hmac.ComputeHash(Payload).Take(4).ToArray());
                }
            }
            else
                return ConnectionSignature;
        }

        public byte[] GenerateKerberosKey(uint pid, string password)
        {
            using (MD5 md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.ASCII.GetBytes(password));
                for (var i = 0; i < 65000 + pid % 1024 - 1; i++)
                    md5.ComputeHash(hash);

                return hash;
            }
        }

        private byte Checksum(byte[] packet)
        {
            var buffer = new int[packet.Length >> 2];
            var sum = new byte[4];

            Buffer.BlockCopy(packet, 0, buffer, 0, buffer.Length << 2);
            Buffer.BlockCopy(new int[] { Sum(buffer) }, 0, sum, 0, 4);

            int checksum = (byte)Encoding.ASCII.GetBytes(_accessKey).Sum(b => b);
            if ((packet.Length & 3) != 0)
                checksum += packet.Skip(packet.Length & ~3).Sum(b => b);

            return (byte)(checksum + sum.Sum(b => b));
        }

        // TODO!
        private int Sum(int[] array)
        {
            var sum = 0;
            foreach (var value in array)
                sum += value;

            return sum;
        }
    }
}
