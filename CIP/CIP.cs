using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace CIPlib
{
    struct TagSymbol
    {
        public int id;
        public string name;
        public short type;
    }

    /// <summary>
    /// CIP-over-TCP/IP encapsulation header
    /// </summary>
    class Header
    {
        // http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf p.17
        public Int16 command;   // 00 - Command - Encapsulation command
        public Int16 length;    // 02 - Length - Length, in bytes, of the data portion of the message
        public Int32 session;   // 04 - Session handle - Session identification (application dependent)
        public Int32 status;    // 08 - Status - Status code
        public Int64 context;   // 12 - Sender context - Information pertinent only to the sender of an encapsulation command
        public Int32 options;   // 20 - Options - Options flags

        public Header(Int16 command, int length, Int32 session = 0)
        {
            this.command = command;
            this.length = (Int16)length;
            this.session = session;
            this.status = 0;
            this.context = 0x0102030405060708;
            this.options = 0;
        }

        public Header(BinaryReader reader)
        {
            command = reader.ReadInt16();
            length = reader.ReadInt16();
            session = reader.ReadInt32();
            status = reader.ReadInt32();
            context = reader.ReadInt64();
            options = reader.ReadInt32();
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(command);
            writer.Write(length);
            writer.Write(session);
            writer.Write(status);
            writer.Write(context);
            writer.Write(options);
        }
    }

    public class CIP
    {
        TcpClient client;
        NetworkStream netStream;
        int _session;

        public CIP(string address, int port = 44818)
        {
            Console.WriteLine("PLC << Connecting");
            client = new TcpClient(address, port);
            netStream = client.GetStream();
        }

        ~CIP()
        {
            if (client != null)
                client.Close();
        }

        void EncaplsulationError(int status)
        {
            // https://www.kepware.com/en-us/products/kepserverex/drivers/allen-bradley-controllogix-ethernet/documents/allen-bradley-controllogix-ethernet-manual/ p.114
            var errors = new Dictionary<int, string>();
            errors[0x01] = "The sender issued an invalid or unsupported encapsulation command.";
            errors[0x02] = "Insufficient memory resources in the receiver to handle the command";
            errors[0x03] = "Poorly formed or incorrect data in the data portion of the encapsulation message.";
            errors[0x64] = "An originator used an invalid session handle when sending an encapsulation message to the target.";
            errors[0x65] = "The target received a message of invalid length.";
            errors[0x69] = "Unsupported encapsulation protocol revision.";

            string errString;
            errors.TryGetValue(status, out errString);
            Console.WriteLine(" << ENCAPSULATION MESSAGE ERROR {0}: {1}", status, errString);
        }

        void CIPError(int status)
        {
            // http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf p.111 
            // https://www.kepware.com/en-us/products/kepserverex/drivers/allen-bradley-controllogix-ethernet/documents/allen-bradley-controllogix-ethernet-manual/ p.114
            var errors = new Dictionary<int, string>();
            errors[0x04] = "A syntax error was detected decoding the Request Path.";
            errors[0x05] = "Request Path destination unknown: Probably instance number is not present.";
            errors[0x06] = "Insufficient Packet Space: Not enough room in the response buffer for all the data.";
            errors[0x08] = "Unsupported service.";
            errors[0x13] = "Insufficient Request Data: Data too short for expected parameters.";
            errors[0x26] = "The Request Path Size received was shorter or longer than expected.";
            errors[0xFF] = "General Error";

            string errString;
            errors.TryGetValue(status, out errString);
            Console.WriteLine("PLC >> CIP ERROR {0}: {1}", status, errString);
        }

        public bool RegisterSession()
        {
            Console.WriteLine("PLC << Registering session");

            MemoryStream memStream = new MemoryStream();
            BinaryWriter mem = new BinaryWriter(memStream);

            Header h = new Header(Commands.RegisterSession, 4);
            h.Write(mem);

            // http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf p.24
            mem.Write((Int16)1);                    // 24 - Protocol version - Requested protocol version shall be set to 1
            mem.Write((Int16)0);                    // 26 - Options flags - Session options shall be set to 0

            memStream.Position = 0;
            memStream.CopyTo(netStream);
            netStream.Flush();

            BinaryReader reader = new BinaryReader(netStream);
            h = new Header(reader);
            var protocol = reader.ReadInt16();
            var options = reader.ReadInt16();

            if (h.status == 0)
            {
                _session = h.session;
                Console.WriteLine("PLC >> Session handle: 0x{0:X}", _session);
                return true;
            }
            else
            {
                EncaplsulationError(h.status);
                return false;
            }
        }

        // REPLY FORMAT
        //65 00 command
        //04 00 len
        //00 10 02 13 handle
        //00 00 00 00 status
        //01 02 03 04 05 06 07 08 context
        //00 00 00 00 options

        //01 00 protocol ver
        //00 00 options

        int MakeRequestPath(byte[] buf, string tagName)
        {
            int lenWords = 0;
            int pos = 1;

            String[] segments = tagName.Split('.');
            foreach (var s in segments)
            {
                byte[] pathBytes = Encoding.ASCII.GetBytes(s);
                int len = pathBytes.Length;
                bool even = (pathBytes.Length % 2 == 0);
                int padded = even ? len : len + 1;
                lenWords += 1 + padded / 2;

                byte[] a = new byte[2 + padded];

                buf[pos++] = 0x91; // 52: Request Path (ANSI extended symbol segment)
                buf[pos++] = (byte)len;
                Array.Copy(pathBytes, 0, buf, pos, len);
                pos += padded;
            }

            buf[0] = (byte)lenWords; // 51: Request Path Size, words

            return pos;
        }

        public bool Read(string tagName)
        {
            byte[] buf = new byte[512];
            int len_path = MakeRequestPath(buf, tagName);

            int len_MR = 1 + len_path + 2;
            int len_data = 10 + len_MR + 4;
            int len_encaps = 16 + len_data;

            Console.WriteLine("PLC << Reading " + tagName);

            MemoryStream memStream = new MemoryStream();
            BinaryWriter mem = new BinaryWriter(memStream);

            Header h = new Header(Commands.SendRRData, len_encaps, _session);
            h.Write(mem);

            // When used to encapsulate the CIP, the SendRRData request and response are used
            // to send encapsulated UCMM messages (unconnected messages).

            mem.Write((Int32)0);                    // 24: Interface handle - shall be 0 for CIP
            mem.Write((Int16)5);                    // 28: Timeout in seconds
            // Encapsulated packet
            mem.Write((Int16)2);                    // 30: Item count - number of items to follow (shall be at least 2)
            mem.Write((Int16)0);                    // 32: Address Type ID
            mem.Write((Int16)0);                    // 34: Address Length
            mem.Write((Int16)0xb2);                 // 36: Data Type ID
            mem.Write((Int16)len_data);              // 38: Data Length
            // CIP Message Router request packet
            mem.Write((byte)0x52);                  // 40: Service (0x52 = Unconnected Send)
            mem.Write((byte)2);                     // 41: Size in words
            mem.Write((byte)0x20);                  // 42: Class id
            mem.Write((byte)0x06);                  // 43: Connection manager
            mem.Write((byte)0x24);                  // 44: Instance ID
            mem.Write((byte)1);                     // 45: Instance Number
            // Unconnected Send Service Parameters
            mem.Write((byte)0x05);                  // 46: Priority or Time tick
            mem.Write((byte)0x99);                  // 47: Time-out ticks
            mem.Write((Int16)len_MR);               // 48: Message Request size, bytes

            // Message Request
            mem.Write(Services.ReadTag);            // 50: Service (0x4C = READ, 0x4D = WRITE)               
            mem.Write(buf, 0, len_path);
            mem.Write((Int16)1);                    // 52 + PathWords*2 : Number of elements to read

            mem.Write((byte)1);                     // Route Path Size, words
            mem.Write((byte)0);                     // Shall be zero
            mem.Write((byte)1);                     // Route Path (0x01 = Backplane)
            mem.Write((byte)0);                     // Route Path Processor Slot


            memStream.Position = 0;
            memStream.CopyTo(netStream);
            netStream.Flush();

            BinaryReader reader = new BinaryReader(netStream);
            h = new Header(reader);

            if (h.status != 0)
            {
                EncaplsulationError(h.status);
                return false;
            }

            var cmd_interface = reader.ReadInt32();
            var cmd_timeout = reader.ReadInt16();

            var encaps_item_count = reader.ReadInt16();
            var encaps_addr_type = reader.ReadInt16();
            var encaps_addr_len = reader.ReadInt16();
            var encaps_data_type = reader.ReadInt16();
            var encaps_data_len = reader.ReadInt16();

            var cip_service = reader.ReadByte();
            var cip_reserved = reader.ReadByte();
            var cip_status = reader.ReadByte();

            if (cip_status == 0) // success
            {
                var cip_addstatus = reader.ReadByte();
                var cip_tag_type = reader.ReadInt16();

                switch (cip_tag_type)
                {
                    case DataTypes.BOOL:
                        var cip_data_b = reader.ReadByte();
                        Console.WriteLine("PLC >> Value: {0}", cip_data_b);
                        break;
                    case DataTypes.SINT:
                        var cip_data8 = reader.ReadByte();
                        Console.WriteLine("PLC >> Value: {0}", cip_data8);
                        break;
                    case DataTypes.INT:
                        var cip_data16 = reader.ReadInt16();
                        Console.WriteLine("PLC >> Value: {0}", cip_data16);
                        break;
                    case DataTypes.DINT:
                        var cip_data32 = reader.ReadInt32();
                        Console.WriteLine("PLC >> Value: {0}", cip_data32);
                        break;
                    case DataTypes.REAL:
                        var cip_dataR = reader.ReadSingle();
                        Console.WriteLine("PLC >> Value: {0}", cip_dataR);
                        break;
                    default: //probably UDT
                        var cip_tag_type_more = reader.ReadInt16();
                        var remain = h.length - 24;
                        for (int i = 0; i < remain; i++)
                            Console.WriteLine("PLC >> Value: 0x{0:X2}", reader.ReadByte());
                        break;
                }

                return true;
            }
            else //error
            {
                var cip_addstatus_size = reader.ReadByte();
                var cip_addstatus = reader.ReadBytes(cip_addstatus_size * 2);
                //var cip_remaining_path = reader.ReadByte();
                CIPError(cip_status);
                return false;
            }
        }

        // REPLY FORMAT: DINT

        // UCMM reply
        // http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf p.39

        //6F 00                     00: command
        //18 00                     02: len
        //00 10 02 13               04: handle
        //03 00 00 00               08: status
        //01 02 03 04 05 06 07 08   12: context
        //00 00 00 00               20: options

        //00 00 00 00               24: interface handle
        //05 00                     28: timeout

        //02 00                     30: item count
        //00 00                     32: address type id
        //00 00                     34: address length
        //B2 00                     36: data type id
        //0A 00                     38: data length

        // Successful Unconnected Send Response
        // http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf p.101

        //CC                        40: reply service (= request service with MSB set to 1)
        //00                        41: shall be zero
        //00                        42: general status: 0 = ok
        //00                        43: shall be zero

        // Unsuccessful Unconnected Send Response
        // http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf p.102

        //CC                        40: reply service: D2 = err
        //00                        41: shall be zero
        //04                        42: general status: 1 = conn fail, 2 = resource unav, 3 = inv par val, 4 = path segm err
        //01                        43: additional status size, words
        //00 00                     44: additional status
        //?                         44+add*2 : remaining path size (only for routing errors)

        // Service Response Data
        // http://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf p.18

        //C4 00                     44: tag type: C4 = DINT 
        //2A 00 00 00               46: data (len = data len - 6)



        // REPLY FORMAT: BOOL

        //CC                        40: reply service (= request service with MSB set to 1)
        //00                        41: shall be zero
        //00                        42: general status: 0 = ok
        //00                        43: shall be zero

        //C1 00 00

        // REPLY FORMAT: STRUCT (IF16)

        //CC                        40: reply service (= request service with MSB set to 1)
        //00                        41: shall be zero
        //00                        42: general status: 0 = ok
        //00                        43: shall be zero

        //A0 02 1F E3               tag type
        //FF FF 00 80               INT 
        //40 40 40 40     
        //20 40 20 40
        //20 40 20 40
        //20 40 20 40       
        //00 b0 24 3b
        //00 b0 24 3b
        //00 b0 24 3b
        //00 10 10 3b

        public bool Write(string tagName, Int32 val)
        {
            byte[] buf = new byte[512];
            int len_path = MakeRequestPath(buf, tagName);

            int len_MR = 1 + len_path + 8;
            int len_data = 10 + len_MR + 4;
            int len_encaps = 16 + len_data;

            Console.WriteLine("PLC << Writing " + tagName + " = " + val);

            MemoryStream memStream = new MemoryStream();
            BinaryWriter mem = new BinaryWriter(memStream);

            Header h = new Header(Commands.SendRRData, len_encaps, _session);
            h.Write(mem);

            // When used to encapsulate the CIP, the SendRRData request and response are used
            // to send encapsulated UCMM messages (unconnected messages).

            mem.Write((Int32)0);                    // 24: Interface handle - shall be 0 for CIP
            mem.Write((Int16)5);                    // 28: Timeout in seconds
            // Encapsulated packet
            mem.Write((Int16)2);                    // 30: Item count - number of items to follow (shall be at least 2)
            mem.Write((Int16)0);                    // 32: Address Type ID
            mem.Write((Int16)0);                    // 34: Address Length
            mem.Write((Int16)0xb2);                 // 36: Data Type ID
            mem.Write((Int16)len_data);              // 38: Data Length
            // CIP Message Router request packet
            mem.Write((byte)0x52);                  // 40: Service (0x52 = Unconnected Send)
            mem.Write((byte)2);                     // 41: Size in words
            mem.Write((byte)0x20);                  // 42: Class id
            mem.Write((byte)0x06);                  // 43: Connection manager
            mem.Write((byte)0x24);                  // 44: Instance ID
            mem.Write((byte)1);                     // 45: Instance Number
            // Unconnected Send Service Parameters
            mem.Write((byte)0x05);                  // 46: Priority or Time tick
            mem.Write((byte)0x99);                  // 47: Time-out ticks
            mem.Write((Int16)len_MR);               // 48: Message Request size, bytes

            // Message Request
            mem.Write(Services.WriteTag);           // 50: Service (0x4C = READ, 0x4D = WRITE)               
            mem.Write(buf, 0, len_path);
            mem.Write(DataTypes.DINT);              // Tag type
            mem.Write((Int16)1);                    // Number of elements to write
            mem.Write(val);                         // Value


            mem.Write((byte)1);                     // Route Path Size, words
            mem.Write((byte)0);                     // Shall be zero
            mem.Write((byte)1);                     // Route Path (0x01 = Backplane)
            mem.Write((byte)0);                     // Route Path Processor Slot


            memStream.Position = 0;
            memStream.CopyTo(netStream);
            netStream.Flush();

            BinaryReader reader = new BinaryReader(netStream);
            h = new Header(reader);

            if (h.status != 0)
            {
                EncaplsulationError(h.status);
                return false;
            }

            var cmd_interface = reader.ReadInt32();
            var cmd_timeout = reader.ReadInt16();

            var encaps_item_count = reader.ReadInt16();
            var encaps_addr_type = reader.ReadInt16();
            var encaps_addr_len = reader.ReadInt16();
            var encaps_data_type = reader.ReadInt16();
            var encaps_data_len = reader.ReadInt16();

            var cip_service = reader.ReadByte();
            var cip_reserved = reader.ReadByte();
            var cip_status = reader.ReadByte();

            if (cip_status == 0) // success
            {
                var cip_addstatus = reader.ReadByte();
                Console.WriteLine("PLC >> Success");
                return true;
            }
            else //error
            {
                var cip_addstatus_size = reader.ReadByte();
                var cip_addstatus = reader.ReadBytes(cip_addstatus_size * 2);
                //var cip_remaining_path = reader.ReadByte();
                CIPError(cip_status);
                return false;
            }
        }

        public bool Write(string tagName, Single val)
        {
            byte[] buf = new byte[512];
            int len_path = MakeRequestPath(buf, tagName);

            int len_MR = 1 + len_path + 8;
            int len_data = 10 + len_MR + 4;
            int len_encaps = 16 + len_data;

            Console.WriteLine("PLC << Writing " + tagName + " = " + val);

            MemoryStream memStream = new MemoryStream();
            BinaryWriter mem = new BinaryWriter(memStream);

            Header h = new Header(Commands.SendRRData, len_encaps, _session);
            h.Write(mem);

            // When used to encapsulate the CIP, the SendRRData request and response are used
            // to send encapsulated UCMM messages (unconnected messages).

            mem.Write((Int32)0);                    // 24: Interface handle - shall be 0 for CIP
            mem.Write((Int16)5);                    // 28: Timeout in seconds
            // Encapsulated packet
            mem.Write((Int16)2);                    // 30: Item count - number of items to follow (shall be at least 2)
            mem.Write((Int16)0);                    // 32: Address Type ID
            mem.Write((Int16)0);                    // 34: Address Length
            mem.Write((Int16)0xb2);                 // 36: Data Type ID
            mem.Write((Int16)len_data);              // 38: Data Length
            // CIP Message Router request packet
            mem.Write((byte)0x52);                  // 40: Service (0x52 = Unconnected Send)
            mem.Write((byte)2);                     // 41: Size in words
            mem.Write((byte)0x20);                  // 42: Class id
            mem.Write((byte)0x06);                  // 43: Connection manager
            mem.Write((byte)0x24);                  // 44: Instance ID
            mem.Write((byte)1);                     // 45: Instance Number
            // Unconnected Send Service Parameters
            mem.Write((byte)0x05);                  // 46: Priority or Time tick
            mem.Write((byte)0x99);                  // 47: Time-out ticks
            mem.Write((Int16)len_MR);               // 48: Message Request size, bytes

            // Message Request
            mem.Write(Services.WriteTag);           // 50: Service (0x4C = READ, 0x4D = WRITE)               
            mem.Write(buf, 0, len_path);
            mem.Write(DataTypes.REAL);              // Tag type
            mem.Write((Int16)1);                    // Number of elements to write
            mem.Write(val);                         // Value


            mem.Write((byte)1);                     // Route Path Size, words
            mem.Write((byte)0);                     // Shall be zero
            mem.Write((byte)1);                     // Route Path (0x01 = Backplane)
            mem.Write((byte)0);                     // Route Path Processor Slot


            memStream.Position = 0;
            memStream.CopyTo(netStream);
            netStream.Flush();

            BinaryReader reader = new BinaryReader(netStream);
            h = new Header(reader);

            if (h.status != 0)
            {
                EncaplsulationError(h.status);
                return false;
            }

            var cmd_interface = reader.ReadInt32();
            var cmd_timeout = reader.ReadInt16();

            var encaps_item_count = reader.ReadInt16();
            var encaps_addr_type = reader.ReadInt16();
            var encaps_addr_len = reader.ReadInt16();
            var encaps_data_type = reader.ReadInt16();
            var encaps_data_len = reader.ReadInt16();

            var cip_service = reader.ReadByte();
            var cip_reserved = reader.ReadByte();
            var cip_status = reader.ReadByte();

            if (cip_status == 0) // success
            {
                var cip_addstatus = reader.ReadByte();
                Console.WriteLine("PLC >> Success");
                return true;
            }
            else //error
            {
                var cip_addstatus_size = reader.ReadByte();
                var cip_addstatus = reader.ReadBytes(cip_addstatus_size * 2);
                //var cip_remaining_path = reader.ReadByte();
                CIPError(cip_status);
                foreach (var b in cip_addstatus)
                    Console.WriteLine("PLC >> Additional status: 0x{0:X}", b);
                return false;
            }
        }

        // REPLY FORMAT
        //CD                        40: reply service (= request service with MSB set to 1)
        //00                        41: shall be zero
        //00                        42: general status: 0 = ok
        //00                        43: shall be zero

        public bool Browse()
        {
            int MRSize = 14;
            int DataLen = 10 + MRSize + 4;
            int EncapsLen = 16 + DataLen;

            Console.WriteLine("PLC << Browsing");

            MemoryStream memStream = new MemoryStream();
            BinaryWriter mem = new BinaryWriter(memStream);

            Header h = new Header(Commands.SendRRData, EncapsLen, _session);
            h.Write(mem);

            mem.Write((Int32)0);                    // 24: Interface handle - shall be 0 for CIP
            mem.Write((Int16)5);                    // 28: Timeout in seconds
            // Encapsulated packet
            mem.Write((Int16)2);                    // 30: Item count - number of items to follow (shall be at least 2)
            mem.Write((Int16)0);                    // 32: Address Type ID
            mem.Write((Int16)0);                    // 34: Address Length
            mem.Write((Int16)0xb2);                 // 36: Data Type ID
            mem.Write((Int16)DataLen);              // 38: Data Length
            // CIP Message Router request packet
            mem.Write((byte)0x52);                  // 40: Service (0x52 = Unconnected Send)
            mem.Write((byte)2);                     // 41: Size in words
            mem.Write((byte)0x20);                  // 42: Class id
            mem.Write((byte)0x06);                  // 43: Connection manager
            mem.Write((byte)0x24);                  // 44: Instance ID
            mem.Write((byte)1);                     // 45: Instance Number
            // Unconnected Send Service Parameters
            mem.Write((byte)0x05);                  // 46: Priority or Time tick
            mem.Write((byte)0x99);                  // 47: Time-out ticks
            mem.Write((Int16)MRSize);               // 48: Message Request size, bytes

            // Message Request
            mem.Write(Services.GetInstanceAttributeList); // 50: Service (0x4C = READ, 0x4D = WRITE)
            mem.Write((byte)3);                     // 51: Request Path Size, words
                                                    // 52: Request Path 
            mem.Write((byte)0x20);                  //   8-bit Class Segment
            mem.Write((byte)0x6B);                  //   Class: 0x6B
            mem.Write((Int16)0x0025);               //   16-bit Instance Segment
            mem.Write((Int16)0x0000);               //   Instance: 0
            mem.Write((Int16)2);                    // Number of attributes to read
            mem.Write((Int16)1);                    // Attribute 1: symbol name
            mem.Write((Int16)2);                    // Attribute 2: symbol type

            mem.Write((byte)1);                     // Route Path Size, words
            mem.Write((byte)0);                     // Shall be zero
            mem.Write((byte)0x01);                  // Route Path (0x01 = Backplane)
            mem.Write((byte)0);                     // Route Path Processor Slot


            memStream.Position = 0;
            memStream.CopyTo(netStream);
            netStream.Flush();

            BinaryReader reader = new BinaryReader(netStream);
            h = new Header(reader);

            if (h.status != 0)
            {
                EncaplsulationError(h.status);
                return false;
            }

            var cmd_interface = reader.ReadInt32();
            var cmd_timeout = reader.ReadInt16();

            var encaps_item_count = reader.ReadInt16();
            var encaps_addr_type = reader.ReadInt16();
            var encaps_addr_len = reader.ReadInt16();
            var encaps_data_type = reader.ReadInt16();
            var encaps_data_len = reader.ReadInt16();

            var cip_service = reader.ReadByte();
            var cip_reserved = reader.ReadByte();
            var cip_status = reader.ReadByte();

            if (cip_status == 0) // success
            {
                var cip_addstatus = reader.ReadByte();

                Console.WriteLine("PLC >> Tags:");
                List<TagSymbol> tags = new List<TagSymbol>();
                while (netStream.DataAvailable)
                {
                    var symbol_id = reader.ReadInt32();
                    var symbol_name_len = reader.ReadInt16();
                    var symbol_name_arr = reader.ReadBytes(symbol_name_len);
                    var symbol_name = Encoding.Default.GetString(symbol_name_arr);
                    var symbol_type = reader.ReadInt16();

                    tags.Add(new TagSymbol { id = symbol_id, name = symbol_name, type = symbol_type });
                    Console.WriteLine(symbol_name);
                }

                return true;
            }
            else //error
            {
                var cip_addstatus_size = reader.ReadByte();
                var cip_addstatus = reader.ReadBytes(cip_addstatus_size * 2);
                Console.WriteLine("PLC >> CIP ERROR: {0:X}", cip_status);
                return false;
            }
        }

        // REPLY FORMAT

        // UCMM reply
        // http://read.pudn.com/downloads166/ebook/763212/EIP-CIP-V2-1.0.pdf p.39

        //6F 00                     00: command
        //FA 00                     02: len
        //00 10 02 13               04: handle
        //00 00 00 00               08: status
        //01 02 03 04 05 06 07 08   12: context
        //00 00 00 00               20: options

        //00 00 00 00               24: interface handle
        //05 00                     28: timeout

        //02 00                     30: item count
        //00 00                     32: address type id
        //00 00                     34: address length
        //B2 00                     36: data type id
        //EA 00                     38: data length

        // Successful Unconnected Send Response
        // http://read.pudn.com/downloads166/ebook/763211/EIP-CIP-V1-1.0.pdf p.101

        //D5                        40: reply service (= request service with MSB set to 1)
        //00                        41: shall be zero
        //00                        42: general status: 0 = ok
        //00                        43: extended status

        // Service Response Data
        // http://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf p.42

        //FA 1B 00 00               First 32-bit Instance ID
        //13 00                     Symbol Name length
        //...                       Symbol Name ("Program:Mainprogram")
        //68 10                     Symbol Type

        //3F 20 00 00
        //09 00
        //...
        //82 8A
    }
}
