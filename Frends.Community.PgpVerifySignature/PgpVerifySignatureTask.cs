using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;

#pragma warning disable 1591

namespace FRENDS.Community.PgpVerifySignature
{

    public class PgpVerifySignatureTask
    {
        /// <summary>
        /// Verifies a PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifySignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static Result PGPVerifySignFile(Input input)
        {
            try
            {
                Stream inputStream = PgpUtilities.GetDecoderStream(File.OpenRead(input.InputFile));

                PgpObjectFactory pgpFact = new PgpObjectFactory(inputStream);
                PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
                PgpOnePassSignature ops = p1[0];

                PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();
                Stream dIn = p2.GetInputStream();
                PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(File.OpenRead(input.PublicKeyFile)));
                PgpPublicKey key = pgpRing.GetPublicKey(ops.KeyId);

                string fosPath;
                if (String.IsNullOrWhiteSpace(input.OutputFolder))
                {
                    fosPath = Path.Combine(Path.GetDirectoryName(input.InputFile), p2.FileName);
                }
                else
                {
                    fosPath = Path.Combine(input.OutputFolder, p2.FileName);
                }
                Stream fos = File.Create(fosPath);

                ops.InitVerify(key);

                int ch;
                while ((ch = dIn.ReadByte()) >= 0)
                {
                    ops.Update((byte)ch);
                    fos.WriteByte((byte)ch);
                }
                fos.Close();

                PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                PgpSignature firstSig = p3[0];
                bool verified = ops.Verify(firstSig);

                Result ret = new Result
                {
                    FilePath = fosPath,
                    Verified = verified
                };

                return ret;
            }
            catch (Exception e)
            {
                Result ret = new Result
                {
                    FilePath = input.OutputFolder,
                    Verified = false
                };

                return ret;
            }

        }
    }
}