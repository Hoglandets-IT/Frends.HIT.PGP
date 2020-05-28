using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using System.Collections;

#pragma warning disable 1591

namespace FRENDS.Community.PgpSignature
{
    public class PgpSignatureTask
    {
        /// <summary>
        /// Sign a file with PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpSignature Returns: Object {string FilePath}
        /// </summary>
        public static Result PGPSignFile(Input input)
        {
            HashAlgorithmTag digest = input.HashFunction.ConvertEnum<HashAlgorithmTag>();

            using (var privateKeyStream = File.OpenRead(input.PrivateKeyFile))
            {
                PgpSecretKey pgpSecKey = ReadSecretKey(privateKeyStream);
                PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(input.Password.ToCharArray());
                PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
                PgpSignatureSubpacketGenerator signatureSubpacketGenerator = new PgpSignatureSubpacketGenerator();

                signatureGenerator.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.BinaryDocument, pgpPrivKey);

                IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
                if (enumerator.MoveNext())
                {
                    signatureSubpacketGenerator.SetSignerUserId(false, (string)enumerator.Current);
                    signatureGenerator.SetHashedSubpackets(signatureSubpacketGenerator.Generate());
                }

                using (var outputStream = File.Create(input.OutputFile))
                {
                    ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
                    BcpgOutputStream bcbgOutputStream = new BcpgOutputStream(armoredOutputStream);
                    signatureGenerator.GenerateOnePassVersion(false).Encode(bcbgOutputStream);

                    FileInfo file = new FileInfo(input.InputFile);
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                    Stream literalDataOut = literalDataGenerator.Open(bcbgOutputStream, PgpLiteralData.Binary, file.Name, file.Length, DateTime.Now);
                    using (var fileIn = file.OpenRead())
                    {
                        int ch;

                        while ((ch = fileIn.ReadByte()) >= 0)
                        {
                            literalDataOut.WriteByte((byte)ch);
                            signatureGenerator.Update((byte)ch);
                        }

                        fileIn.Close();
                        literalDataGenerator.Close();
                        signatureGenerator.Generate().Encode(bcbgOutputStream);
                        armoredOutputStream.Close();
                        outputStream.Close();

                        Result ret = new Result
                        {
                            FilePath = input.OutputFile
                        };
                        return ret;
                    }
                }
            }
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
    }
}