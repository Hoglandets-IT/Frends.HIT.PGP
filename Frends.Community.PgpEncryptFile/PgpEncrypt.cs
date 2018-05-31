using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

#pragma warning disable 1591

namespace Frends.Community.PgpEncrypt
{

    public class PgpEncryptFileTask
    {
        /// <summary>
        /// Encrypts a file using public key.
        /// If needed, the file can also be signed with private key, in this case, the order is sign and encrypt.
        /// </summary>
        /// <param name="input"></param>
        /// <returns>Result.FilePath string</returns>
        public static Result PgpEncryptFile(Input input)
        {
            const int BUFFER_SIZE = 1 << 16;
            FileInfo inputFile = new FileInfo(input.InputFile);
            Stream outputStream = null;

            try
            {
                // destination file
                outputStream = File.OpenWrite(input.OutputFile);

                using (outputStream)
                {
                    if (input.UseArmor)
                    {
#pragma warning disable CS0728 // Possibly incorrect assignment to local which is the argument to a using or lock statement - intended behaviour
                        outputStream = new ArmoredOutputStream(outputStream);
#pragma warning restore CS0728
                    }

                    //
                    // public key setup
                    //
                    SymmetricKeyAlgorithmTag algorithmTag = input.EncryptionAlgorithm.ConvertEnum<SymmetricKeyAlgorithmTag>();
                    PgpPublicKey publicKey = ReadPublicKey(input.PublicKeyFile);
                    PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(algorithmTag, input.UseIntegrityCheck, new SecureRandom());
                    encryptedDataGenerator.AddMethod(publicKey);

                    using (Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]))
                    {
                        //
                        // compression setup - by default, use compression
                        //
                        CompressionAlgorithmTag compressionTag = input.CompressionType.ConvertEnum<CompressionAlgorithmTag>();
                        PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(compressionTag);
                        Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

                        //
                        // signature setup - if necessary
                        //
                        PgpSignatureGenerator signatureGenerator = null;
                        if (input.SignWithPrivateKey)
                        {
                            HashAlgorithmTag hashAlgorithm = input.SigningSettings.SignatureHashAlgorithm.ConvertEnum<HashAlgorithmTag>();
                            signatureGenerator = GetPgpSignatureGenerator(input.SigningSettings.PrivateKeyFile, input.SigningSettings.PrivateKeyPassword, hashAlgorithm);
                            signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
                        }

                        //
                        // literal data generator setup and writing encrypted file
                        //
                        PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                        using (Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, inputFile))
                        using (FileStream inputStream = inputFile.OpenRead())
                        {
                            byte[] buf = new byte[BUFFER_SIZE];
                            int len;

                            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
                            {
                                literalOut.Write(buf, 0, len);
                                if (input.SignWithPrivateKey)
                                {
                                    signatureGenerator.Update(buf, 0, len);
                                }
                            }
                        }
                        literalDataGenerator.Close();

                        if (input.SignWithPrivateKey)
                        {
                            signatureGenerator.Generate().Encode(outputStream);
                        }
                    }

                    encryptedDataGenerator.Close();

                    if (input.UseArmor)
                    {
                        // has to be explicitly closed, otherwise pgp ascii suffix won't be written
                        outputStream.Close();
                    }

                    return new Result
                    {
                        FilePath = input.OutputFile
                    };
                }
            }
            catch (PgpException e)
            {
                throw;
            }
        }

        /// <summary>
        /// Find first suitable public key for encryption.
        /// </summary>
        /// <param name="publicKeyFile"></param>
        /// <returns></returns>
        private static PgpPublicKey ReadPublicKey(string publicKeyFile)
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
        /// <param name="privateKeyFile">Path to privateKey</param>
        /// <param name="privateKeyPassword">Password to privateKey</param>
        /// <param name="hashAlgorithm">Hash algorithm to use</param>
        /// <returns>PgpSignatureGenerator to be used when signing a file</returns>
        private static PgpSignatureGenerator GetPgpSignatureGenerator(string privateKeyFile, string privateKeyPassword, HashAlgorithmTag hashAlgorithm)
        {
            try
            {
                PgpSecretKey secretKey = ReadSecretKey(privateKeyFile);
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(privateKeyPassword.ToCharArray());

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
        /// <param name="privateKeyFile">Path to privateKey file</param>
        /// <returns>PgpSecretKey of the given privateKey</returns>
        private static PgpSecretKey ReadSecretKey(string privateKeyFile)
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
    }
}