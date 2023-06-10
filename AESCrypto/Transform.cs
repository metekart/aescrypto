using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AESCrypto
{
    public static class Transform
    {
        public static string ToHexaDecimalString(byte[] inArray, int offset, int length, string sep = "")
        {
            string hexValue = BitConverter.ToString(inArray, offset, length);

            return hexValue.Replace("-", sep);
        }

        public static string ToHexaDecimalString(byte[] inArray, string sep = "")
        {
            string hexValue = BitConverter.ToString(inArray);

            return hexValue.Replace("-", sep);
        }

        public static byte[] FromHexaDecimalString(string hexValue, string sep = "")
        {
            hexValue = Regex.Replace(hexValue, sep, "");

            int len = hexValue.Length;
            byte[] byteArray = new byte[len / 2];

            try
            {
                for (int i = 0; i < len; i += 2)
                    byteArray[i / 2] = Convert.ToByte(hexValue.Substring(i, 2), 16);
            }
            catch (Exception e)
            {
                throw e;
            }

            return byteArray;
        }
    }
}
