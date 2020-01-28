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

            using (var inputStream = PgpUtilities.GetDecoderStream(File.OpenRead(input.InputFile)))
            {
                PgpObjectFactory pgpFact = new PgpObjectFactory(inputStream);
                PgpOnePassSignatureList signatureList = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
                PgpOnePassSignature onePassSignature = signatureList[0];

                PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();
                Stream dataIn = p2.GetInputStream();
                PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(File.OpenRead(input.PublicKeyFile)));
                PgpPublicKey key = pgpRing.GetPublicKey(onePassSignature.KeyId);

                string outputPath;
                if (String.IsNullOrWhiteSpace(input.OutputFolder))
                {
                    outputPath = Path.Combine(Path.GetDirectoryName(input.InputFile), p2.FileName);
                }
                else
                {
                    outputPath = Path.Combine(input.OutputFolder, p2.FileName);
                }
                using (var outputStream = File.Create(outputPath))
                {
                    onePassSignature.InitVerify(key);

                    int ch;
                    while ((ch = dataIn.ReadByte()) >= 0)
                    {
                        onePassSignature.Update((byte)ch);
                        outputStream.WriteByte((byte)ch);
                    }
                    outputStream.Close();
                }

                bool verified;
                // Will throw Exception if file is altered
                try
                {
                    PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                    PgpSignature firstSig = p3[0];
                    verified = onePassSignature.Verify(firstSig);
                }
                catch (Exception)
                {
                    Result retError = new Result
                    {
                        FilePath = input.OutputFolder,
                        Verified = false
                    };

                    return retError;
                }

                Result ret = new Result
                {
                    FilePath = outputPath,
                    Verified = verified
                };

                return ret;
            }
        }
    }
}
