using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Frends.Tasks.Attributes;
using System.ComponentModel;

#pragma warning disable 1591

namespace FRENDS.Community.PgpEncrypt
{
    public class Input
    {
        /// <summary>
        /// Path to file being encrypted.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        public string InputFile { get; set; }
        /// <summary>
        /// Path to encrypted file that will be create.
        /// </summary>
        [DefaultValue(@"C:\temp\encryptedFile.pgp")]
        public string OutputFile { get; set; }
        /// <summary>
        /// Path to recipients public key.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        public string PublicKeyFile { get; set; }
        /// <summary>
        /// Use ascii armor or not.
        /// </summary>
        [DefaultValue("true")]
        public bool Armor { get; set; }
        /// <summary>
        /// Check integrity of output file or not.
        /// </summary>
        [DefaultValue("true")]
        public bool UseIntegrityCheck { get; set; }
    }

    public class Result
    {
        /// <summary>
        /// Result class.
        /// </summary>
        public string FilePath { get; set; }
    }
    public class FRENDSTaskEncrypt
    {
        /// <summary>
        /// Encrypt the file using the public key of the intended recipients.
        /// </summary>
        public static bool PgpEncrypt(Input input)
        {
            try
            {
                using (Stream publicKeyStream = File.OpenRead(input.PublicKeyFile))
                {
                    PgpPublicKey encKey = ReadPublicKey(publicKeyStream);

                    using (MemoryStream bOut = new MemoryStream())
                    {
                        PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                        PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(input.InputFile));

                        comData.Close();
                        PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, input.UseIntegrityCheck, new SecureRandom());

                        cPk.AddMethod(encKey);
                        byte[] bytes = bOut.ToArray();

                        using (Stream outputStream = File.Create(input.OutputFile))
                        {
                            if (input.Armor)
                            {
                                using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                                {
                                    using (Stream cOut = cPk.Open(armoredStream, bytes.Length))
                                    {
                                        cOut.Write(bytes, 0, bytes.Length);
                                    }
                                }
                            }
                            else
                            {
                                using (Stream cOut = cPk.Open(outputStream, bytes.Length))
                                {
                                    cOut.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                    }
                    return true;
                }
            }
            catch (PgpException e)
            {
                throw;
            }
        }

        /// <summary>
        /// Return the first key we can use to encrypt.
        /// Note: A file can contain multiple keys (stored in "key rings"), 
        /// but we just loop through the collection till we find a key suitable for encryption, 
        /// in the real world you would probably want to be a bit smarter about this.
        /// </summary>
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }
    }
}