using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Utilities.IO;

#pragma warning disable 1591

namespace FRENDS.Community.PgpDecrypt
{
    public class FRENDSTaskDecrypt
    {
        /*
        * decrypt a given file.
        */

        public static bool PgpDecrypt(string inputfile, string privateKeyFile, string passPhrase, string outputFile)
        {
            if (!File.Exists(inputfile))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputfile));

            if (!File.Exists(privateKeyFile))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFile));

            if (String.IsNullOrEmpty(outputFile))
                throw new ArgumentNullException("Invalid Output file path.");

            using (Stream inputStream = File.OpenRead(inputfile))
            {
                using (Stream keyIn = File.OpenRead(privateKeyFile))
                {
                    Decrypt(inputStream, keyIn, passPhrase, outputFile);
                }
            }
            return true;
        }

        private static bool Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
        {
            try
            {
                PgpObjectFactory pgpF = null;
                PgpEncryptedDataList enc = null;
                PgpObject o = null;
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = null;

                pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                // find secret key
                pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpF != null)
                    o = pgpF.NextPgpObject();

                // the first object might be a PGP marker packet.
                if (o is PgpEncryptedDataList)
                    enc = (PgpEncryptedDataList)o;
                else
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                // decrypt
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                    throw new ArgumentException("Secret key for message not found.");

                PgpObjectFactory plainFact = null;

                using (Stream clear = pbe.GetDataStream(sKey))
                {
                    plainFact = new PgpObjectFactory(clear);
                }

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory of = null;

                    using (Stream compDataIn = cData.GetDataStream())
                    {
                        of = new PgpObjectFactory(compDataIn);
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        message = of.NextPgpObject();
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                    else
                    {
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;

                    using (Stream fOut = File.Create(outputFile))
                    {
                        Stream unc = ld.GetInputStream();
                        Streams.PipeAll(unc, fOut);
                    }
                }
                else if (message is PgpOnePassSignatureList)
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                else
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");

                return true;

            }
            catch (PgpException ex)
            {
                throw;
            }
        }


        /*
        * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        */

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }


    }
}


