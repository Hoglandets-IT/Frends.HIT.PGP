using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using System.Collections;

#pragma warning disable 1591

namespace FRENDS.Community.PgpClearTextSignature
{
    public class PgpClearTextSignatureTask
    {
        /// <summary>
        /// Create a file with PGP clear text signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpClearTextSignature Returns: Object {string FilePath}
        /// </summary>
        public static Result PGPClearTextSignFile(Input input)
        {
            HashAlgorithmTag digest;
            if (input.HashFunction == HashFunctionType.MD5)
            {
                digest = HashAlgorithmTag.MD5;
            }
            else if (input.HashFunction == HashFunctionType.RipeMD160)
            {
                digest = HashAlgorithmTag.RipeMD160;
            }
            else if (input.HashFunction == HashFunctionType.Sha1)
            {
                digest = HashAlgorithmTag.Sha1;
            }
            else if (input.HashFunction == HashFunctionType.Sha224)
            {
                digest = HashAlgorithmTag.Sha224;
            }
            else if (input.HashFunction == HashFunctionType.Sha384)
            {
                digest = HashAlgorithmTag.Sha384;
            }
            else if (input.HashFunction == HashFunctionType.Sha512)
            {
                digest = HashAlgorithmTag.Sha512;
            }
            else
            {
                digest = HashAlgorithmTag.Sha256;
            }

            Stream privateKeyStream = File.OpenRead(input.PrivateKeyFile);

            PgpSecretKey pgpSecKey = ReadSecretKey(privateKeyStream);
            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(input.Password.ToCharArray());
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();

            sGen.InitSign(PgpSignature.CanonicalTextDocument, pgpPrivKey);

            IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            Stream fIn = File.OpenRead(input.InputFile);
            Stream outputStream = File.Create(input.OutputFile);

            ArmoredOutputStream aOut = new ArmoredOutputStream(outputStream);

            aOut.BeginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = ReadInputLine(lineOut, fIn);

            ProcessLine(aOut, sGen, lineOut.ToArray());

            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, fIn);

                    sGen.Update((byte)'\r');
                    sGen.Update((byte)'\n');

                    ProcessLine(aOut, sGen, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            fIn.Close();

            aOut.EndClearText();

            BcpgOutputStream bOut = new BcpgOutputStream(aOut);

            sGen.Generate().Encode(bOut);

            aOut.Close();
            outputStream.Close();

            Result ret = new Result
            {
                FilePath = input.OutputFile
            };

            return ret;
        }

        private static int ReadInputLine(
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

        private static int ReadInputLine(
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
    
        private static void ProcessLine(
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

    }

}