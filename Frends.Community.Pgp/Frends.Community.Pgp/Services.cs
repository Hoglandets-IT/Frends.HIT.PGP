using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

using FRENDS.Community.Pgp;

#pragma warning disable 1591


namespace Frends.Community.Pgp
{

    #region PgpClearTextSignature
    public static class Services
    {
        internal static int ReadInputLine(
        MemoryStream bOut,
        Stream fIn)
        {
            bOut.SetLength(0);

            int lookAhead = -1;
            int ch;

            while ((ch = fIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }

            return lookAhead;
        }

        internal static int PgpVerifyClearTextSignatureReadInputLine(MemoryStream bOut, int lookAhead, Stream fIn)
        {
            bOut.SetLength(0);

            int ch = lookAhead;

            do
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }
            while ((ch = fIn.ReadByte()) >= 0);

            if (ch < 0)
            {
                lookAhead = -1;
            }

            return lookAhead;
        }

        internal static int ReadInputLine(
            MemoryStream bOut,
            int lookAhead,
            Stream fIn)
        {
            bOut.SetLength(0);

            int ch = lookAhead;

            do
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }
            while ((ch = fIn.ReadByte()) >= 0);

            if (ch < 0)
            {
                lookAhead = -1;
            }

            return lookAhead;
        }



        internal static int PgpVerifyClearTextSignatureReadInputLine(MemoryStream bOut, Stream fIn)
        {
            bOut.SetLength(0);

            int lookAhead = -1;
            int ch;

            while ((ch = fIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
                if (ch == '\r' || ch == '\n')
                {
                    lookAhead = ReadPassedEol(bOut, ch, fIn);
                    break;
                }
            }

            return lookAhead;
        }


        internal static PgpSecretKey ReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        private static int ReadPassedEol(
        MemoryStream bOut,
        int lastCh,
        Stream fIn)
        {
            int lookAhead = fIn.ReadByte();

            if (lastCh == '\r' && lookAhead == '\n')
            {
                bOut.WriteByte((byte)lookAhead);
                lookAhead = fIn.ReadByte();
            }

            return lookAhead;
        }




        internal static void ProcessLine(
            Stream aOut,
            PgpSignatureGenerator sGen,
            byte[] line)
        {
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sGen.Update(line, 0, length);
            }

            aOut.Write(line, 0, line.Length);
        }

        private static int GetLengthWithoutWhiteSpace(
    byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }

        private static bool IsWhiteSpace(
    byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }


        private static bool IsLineEnding(
    byte b)
        {
            return b == '\r' || b == '\n';
        }


        #endregion

        #region PgpDecrypt
        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        /// </summary>
        internal static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        #endregion

        #region PgpEncrypt
        /// <summary>
        /// Helper for getting encryption stream
        /// </summary>
        /// <param name="stream">Stream to chain for encryption</param>
        /// <param name="input">Task settings</param>
        /// <returns>Encryption chained stream</returns>
        internal static Stream GetEncryptionStream(Stream stream, PgpEncryptInput input)
        {
            SymmetricKeyAlgorithmTag algorithmTag = input.EncryptionAlgorithm.ConvertEnum<SymmetricKeyAlgorithmTag>();
            PgpPublicKey publicKey = ReadPublicKey(input.PublicKeyFile);
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(algorithmTag, input.UseIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(publicKey);
            return encryptedDataGenerator.Open(stream, new byte[PgpTasks.PGP_ENCRYPT_BUFFER_SIZE]);
        }

        /// <summary>
        /// Gets compression stream if compression is needed, otherwise returns original stream
        /// </summary>
        /// <param name="stream">Source stream</param>
        /// <param name="input">Task input</param>
        /// <returns>Compression chained stream or original source</returns>
        internal static Stream GetCompressionStream(Stream stream, PgpEncryptInput input)
        {
            if (input.UseArmor)
            {
                CompressionAlgorithmTag compressionTag = input.CompressionType.ConvertEnum<CompressionAlgorithmTag>();
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(compressionTag);
                return compressedDataGenerator.Open(stream);
            }
            return stream;
        }

        /// <summary>
        /// Find first suitable public key for encryption.
        /// </summary>
        /// <param name="publicKeyFile">Path to public key file</param>
        /// <returns>PgpPublicKey from public key file location</returns>
        internal static PgpPublicKey ReadPublicKey(string publicKeyFile)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
            using (Stream decoderStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(decoderStream);

                foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey k in kRing.GetPublicKeys())
                    {
                        if (k.IsEncryptionKey)
                            return k;
                    }
                }
            }
            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Helper for creating a PgpSignatureGenerator from private key file and its password
        /// </summary>
        /// <param name="stream">Stream to use for signature initialization</param>
        /// <param name="input">Encryption task input</param>
        /// <returns>PgpSignatureGenerator to be used when signing a file</returns>
        internal static PgpSignatureGenerator InitPgpSignatureGenerator(Stream stream, PgpEncryptInput input)
        {
            HashAlgorithmTag hashAlgorithm = input.SigningSettings.SignatureHashAlgorithm.ConvertEnum<HashAlgorithmTag>();

            try
            {
                PgpSecretKey secretKey = ReadSecretKey(input.SigningSettings.PrivateKeyFile);
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(input.SigningSettings.PrivateKeyPassword.ToCharArray());

                var pgpSignatureGenerator = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, hashAlgorithm);
                pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);

                foreach (string userId in secretKey.PublicKey.GetUserIds())
                {
                    PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                    spGen.SetSignerUserId(false, userId);
                    pgpSignatureGenerator.SetHashedSubpackets(spGen.Generate());
                    // Just the first one!
                    break;
                }

                pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(stream);
                return pgpSignatureGenerator;
            }
            catch (PgpException e)
            {
                throw new Exception("Private key extraction failed, password might be incorrect", e);
            }
        }

        /// <summary>
        /// Reads secret key from given privateKey
        /// </summary>
        /// <param name="privateKeyFile">Path to private key file</param>
        /// <returns>PgpSecretKey of the given privateKey</returns>
        internal static PgpSecretKey ReadSecretKey(string privateKeyFile)
        {
            PgpSecretKey secretKey = null;

            using (Stream secretKeyStream = File.OpenRead(privateKeyFile))
            {
                var secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(secretKeyStream));

                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                    {
                        if (key.IsSigningKey)
                            secretKey = key;
                    }
                }

                if (secretKey == null)
                    throw new Exception("Wrong private key - Can't find signing key in key ring.");
            }

            return secretKey;
        }
        #endregion

        #region PgpSignature


        internal static PgpSecretKey PgpSignatureReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        #endregion

        #region PgpVerifyClearTextSignature


        internal static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }


        internal static void ProcessLine(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature sig, byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sig.Update(line, 0, length);
            }
        }



#endregion

    }
}
