using System;

namespace CIPlib
{
    /// <summary>
    /// Encapsulation commands
    /// </summary>
    public static class Commands
    {
        public const Int16 ListIdentity = 0x63;
        public const Int16 ListInterfaces = 0x64;
        public const Int16 RegisterSession = 0x65;
        public const Int16 UnRegisterSession = 0x66;
        public const Int16 SendRRData = 0x6F;
    }

    /// <summary>
    /// Tag Type Service Parameter Values Used with Logix Controllers
    /// </summary>
    public static class DataTypes
    {
        public const Int16 BOOL = 0xC1;
        public const Int16 SINT = 0xC2;
        public const Int16 INT = 0xC3;
        public const Int16 DINT = 0xC4;
        public const Int16 REAL = 0xCA;
    }

    /// <summary>
    /// Services Supported by Logix5000 Controllers
    /// </summary>
    public static class Services
    {
        public const byte GetAttributesAll = 0x01;
        public const byte GetAttributeList = 0x03;
        public const byte Create = 0x08;
        public const byte MultipleServicePacket = 0x0A;
        public const byte ReadTag = 0x4C;
        public const byte WriteTag = 0x4D;
        public const byte ReadModifyWriteTag = 0x4E;
        public const byte ReadTagFragmented = 0x52;
        public const byte WriteTagFragmented = 0x53;
        public const byte GetInstanceAttributeList = 0x55;
    }
}
