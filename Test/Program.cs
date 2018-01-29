using System;
using CIPlib;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                CIP c = new CIP("192.168.0.222");
                c.RegisterSession();
                c.Browse();

                //c.Read("Teeq");                    // DINT: ok
                //c.Read("Local:2:I");               // UDT: byte array [TODO]
                //c.Read("Local:2:I.Ch0Data");       // UDT member: REAL - ok
                //c.Read("ints.a");                  // UDT member: DINT - ok
                //c.Read("ints.b");                  // UDT member: INT - ok
                //c.Read("V1.diOp");                 // UDT member: BOOL - ok
                //c.Read("Local:2:C.Ch0Config.RangeType");  // nested UDT: ok

                /*while (ok)
                {
                    c.Read("Local:2:I.Ch0Data");
                    Thread.Sleep(1000);
                }*/

                //c.Write("Teeq", 9);                   // writing DINT: ok
                //c.Read("Teeq");

                c.Write("Local:3:O.Ch6Data", 4.23f);    // writing REAL: ok
                c.Read("Local:3:O.Ch6Data");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            Console.WriteLine("bye");
            Console.ReadLine();
        }
    }
}
