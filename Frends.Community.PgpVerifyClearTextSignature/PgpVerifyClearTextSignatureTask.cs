using System;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using System.Text;

#pragma warning disable 1591

namespace FRENDS.Community.PgpVerifyClearTextSignature
{

    public class PgpVerifyClearTextSignatureTask
    {
        /// <summary>
        /// Verifies clear text PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifyClearTextSignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static Result PGPVerifyClearTextSignFile(Input input)
        {
            Stream inStr = File.OpenRead(input.InputFile);
            ArmoredInputStream aIn = new ArmoredInputStream(inStr);
            Stream outStr = File.Create(input.OutputFile);

            //
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = ReadInputLine(lineOut, aIn);
            byte[] lineSep = Encoding.ASCII.GetBytes(Environment.NewLine); ;


            if (lookAhead != -1 && aIn.IsClearText())
            {
                byte[] line = lineOut.ToArray();
                outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                outStr.Write(lineSep, 0, lineSep.Length);

                while (lookAhead != -1 && aIn.IsClearText())
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, aIn);

                    line = lineOut.ToArray();
                    outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(lineSep, 0, lineSep.Length);
                }
            }
            else
            {
                // a single line file
                if (lookAhead != -1)
                {
                    byte[] line = lineOut.ToArray();
                    outStr.Write(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(lineSep, 0, lineSep.Length);
                }
            }
            outStr.Close();

            PgpPublicKeyRingBundle pgpRings = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(File.OpenRead(input.PublicKeyFile)));

            PgpObjectFactory pgpFact = new PgpObjectFactory(aIn);
            PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature sig = p3[0];
            inStr.Close();

            sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));
            // read the input, making sure we ignore the last newline.
            Stream sigIn = File.OpenRead(input.OutputFile);
            lookAhead = ReadInputLine(lineOut, sigIn);
            ProcessLine(sig, lineOut.ToArray());
            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = ReadInputLine(lineOut, lookAhead, sigIn);

                    sig.Update((byte)'\r');
                    sig.Update((byte)'\n');

                    ProcessLine(sig, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            bool verified = sig.Verify();
            sigIn.Close();
            Result ret = new Result
            {
                FilePath = input.OutputFile,
                Verified = verified
            };

            return ret;

        }

        private static int ReadInputLine(MemoryStream bOut, int lookAhead, Stream fIn)
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

        private static int ReadInputLine(MemoryStream bOut, Stream fIn)
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

        private static int ReadPassedEol(MemoryStream bOut, int lastCh, Stream fIn)
        {
            int lookAhead = fIn.ReadByte();

            if (lastCh == '\r' && lookAhead == '\n')
            {
                bOut.WriteByte((byte)lookAhead);
                lookAhead = fIn.ReadByte();
            }

            return lookAhead;
        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }
        private static bool IsWhiteSpace(byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

        private static bool IsLineEnding(byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static void ProcessLine(PgpSignature sig, byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            int length = GetLengthWithoutWhiteSpace(line);
            if (length > 0)
            {
                sig.Update(line, 0, length);
            }
        }

        private static int GetLengthWithoutWhiteSpace(byte[] line)
        {
            int end = line.Length - 1;

            while (end >= 0 && IsWhiteSpace(line[end]))
            {
                end--;
            }

            return end + 1;
        }
    }
}