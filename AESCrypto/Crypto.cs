using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace AESCrypto
{
    public static class Crypto
    {
        private const int BLOCK_LENGTH = 24;

        private static byte[] pattern = { 
                0x5D, 0xC5, 0xBC, 0xBE, 0xBC, 0x54, 0xF0, 0xF1,
                0x6E, 0x30, 0x52, 0x76, 0xCA, 0x47, 0x44, 0x61,
                0x77, 0x5D, 0xBF, 0x07, 0x0D, 0x21, 0x93, 0x0B
        };

        private static byte[] key = {
                0xAB, 0xCC, 0xF4, 0x43, 0x56, 0x56, 0x66, 0x54,
                0x19, 0xF4, 0xC3, 0x6F, 0x74, 0x35, 0x6E, 0xDD
        };

        public static bool Encrypt(string plainText, out string encString, SymmetricAlgorithmType encType = SymmetricAlgorithmType.AES)
        {
            byte[] dataArray = UTF8Encoding.UTF8.GetBytes(plainText);
            byte[] procArray = new byte[BLOCK_LENGTH];

            int dataLen = dataArray.Length;
            encString = "";

            if (dataLen >= BLOCK_LENGTH)
                return false;

            procArray[0] = (byte)dataLen;

            for (int i = 1; i <= dataLen; i++)
                procArray[i] = dataArray[i - 1];

            for (int i = dataLen + 1; i < BLOCK_LENGTH; i++)
                procArray[i] = procArray[i - dataLen];

            for (int i = 0; i < BLOCK_LENGTH; i++)
                procArray[i] ^= pattern[i];

            SymmetricAlgorithm algorithm = null;

            switch (encType) {
                case SymmetricAlgorithmType.AES:
                    algorithm = new AesCryptoServiceProvider();
                    break;
                case SymmetricAlgorithmType.RC2:
                    algorithm = new RC2CryptoServiceProvider();
                    break;
                case SymmetricAlgorithmType.TripleDES:
                    algorithm = new TripleDESCryptoServiceProvider();
                    break;
            }

            algorithm.Key = key;
            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.PKCS7;

            ICryptoTransform cryptoTransform = algorithm.CreateEncryptor();
            byte[] resArray = cryptoTransform.TransformFinalBlock(procArray, 0, procArray.Length);

            algorithm.Clear();

            encString = Transform.ToHexaDecimalString(resArray, 0, resArray.Length);

            return true;
        }

        public static bool Decrypt(string cipherText, out string decString, SymmetricAlgorithmType decType = SymmetricAlgorithmType.AES)
        {
            bool ret = false;
            decString = cipherText;

            try
            {
                byte[] procArray = Transform.FromHexaDecimalString(cipherText);

                SymmetricAlgorithm algorithm = null;

                switch (decType) {
                    case SymmetricAlgorithmType.AES:
                        algorithm = new AesCryptoServiceProvider();
                        break;
                    case SymmetricAlgorithmType.RC2:
                        algorithm = new RC2CryptoServiceProvider();
                        break;
                    case SymmetricAlgorithmType.TripleDES:
                        algorithm = new TripleDESCryptoServiceProvider();
                        break;
                }

                algorithm.Key = key;
                algorithm.Mode = CipherMode.ECB;
                algorithm.Padding = PaddingMode.PKCS7;

                ICryptoTransform cryptoTransform = algorithm.CreateDecryptor();
                byte[] resArray = cryptoTransform.TransformFinalBlock(procArray, 0, procArray.Length);

                algorithm.Clear();

                if (resArray.Length < BLOCK_LENGTH)
                    return ret;

                for (int i = 0; i < BLOCK_LENGTH; i++)
                    resArray[i] ^= pattern[i];

                int dataLen = resArray[0];

                if (dataLen >= BLOCK_LENGTH)
                    return ret;

                byte[] dataArray = new byte[dataLen];

                Array.Copy(resArray, 1, dataArray, 0, dataLen);
                decString = UTF8Encoding.UTF8.GetString(dataArray);
                ret = true;
            }
            catch (Exception)
            {
            }

            return ret;
        }
    }

    public enum SymmetricAlgorithmType
    {
        AES,
        RC2,
        TripleDES
    }
}
