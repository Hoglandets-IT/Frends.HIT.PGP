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

            sGen.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.BinaryDocument, pgpPrivKey);

            IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            Stream outputStream = File.Create(input.OutputFile);
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
            BcpgOutputStream bOut = new BcpgOutputStream(armoredOutputStream);
            sGen.GenerateOnePassVersion(false).Encode(bOut);

            FileInfo file = new FileInfo(input.InputFile);
            PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
            Stream lOut = lGen.Open(bOut, PgpLiteralData.Binary, file);
            FileStream fIn = file.OpenRead();
            int ch;

            while ((ch = fIn.ReadByte()) >= 0)
            {
                lOut.WriteByte((byte)ch);
                sGen.Update((byte)ch);
            }

            fIn.Close();
            lGen.Close();
            sGen.Generate().Encode(bOut);
            armoredOutputStream.Close();
            outputStream.Close();

            Result ret = new Result
            {
                FilePath = input.OutputFile
            };
            return ret;
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