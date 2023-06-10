using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AESCrypto
{
    class Program
    {
        static void Main(string[] args)
        {
            string encrypted, decrypted;

            Crypto.Encrypt("mete", out encrypted);
            Console.WriteLine(encrypted);
            Crypto.Decrypt(encrypted, out decrypted);

            Console.WriteLine(decrypted);
            Console.ReadKey();
        }
    }
}
