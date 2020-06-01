using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Utilities.IO;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

#pragma warning disable 1591

namespace FRENDS.Community.PgpDecrypt
{
    public class Input
    {

        /// <summary>
        /// Path to file to decrypt.
        /// </summary>
        [DefaultValue(@"C:\temp\encryptedFile.pgp")]
        [DisplayFormat(DataFormatString = "Text")] 
        public string InputFile { get; set; }
        /// <summary>
        /// Path to file that will be create.
        /// </summary>
        [DefaultValue(@"C:\temp\decrypted_file.txt")]
        [DisplayFormat(DataFormatString = "Text")] 
        public string OutputFile { get; set; }
        /// <summary>
        /// Private key used to decrypt file.
        /// </summary>
        [DefaultValue(@"C:\temp\privateKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PrivateKeyFile { get; set; }
        /// <summary>
        /// Password for private key.
        /// </summary>
        [PasswordPropertyText]
        public string PassPhrase { get; set; }

    }
    public class Result
    {
        /// <summary>
        /// Result class.
        /// </summary>
        public string FilePath { get; set; }
    }


    public class PgpDecryptFileTask
    {
        /// <summary>
        /// Decrypt the file using the private key.
        /// </summary>
        public static Result PgpDecryptFile(Input input)
        {
            if (!File.Exists(input.InputFile))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", input.InputFile));

            if (!File.Exists(input.PrivateKeyFile))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", input.PrivateKeyFile));

            if (String.IsNullOrEmpty(input.OutputFile))
                throw new ArgumentNullException("Invalid Output file path.");

            using (Stream inputStream = File.OpenRead(input.InputFile))
            {
                using (Stream keyIn = File.OpenRead(input.PrivateKeyFile))
                {
                    Decrypt(inputStream, keyIn, input.PassPhrase, input.OutputFile);
                }
            }
            Result ret = new Result
            {
                FilePath = input.OutputFile
            };

            return ret;
        }

        private static bool Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
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


