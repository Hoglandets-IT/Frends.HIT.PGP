using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

#pragma warning disable 1591

namespace Frends.Community.PgpEncrypt
{
    public class PgpEncryptFileTask
    {
        private const int BUFFER_SIZE = 1 << 16;

        /// <summary>
        /// Encrypts a file using public key.
        /// If needed, the file can also be signed with private key, in this case, the order is sign and encrypt.
        /// See https://github.com/CommunityHiQ/Frends.Community.PgpEncryptFile
        /// </summary>
        /// <param name="input">Task input</param>
        /// <returns>Returns: Object {string FilePath}</returns>
        public static Result PgpEncryptFile(Input input)
        {
            // source file to encrypt
            FileInfo inputFile = new FileInfo(input.InputFile);

            if (!inputFile.Exists)
                throw new ArgumentException("File to encrypt does not exists", "input.InputFile");
            
            try
            {
                // destination file
                using (Stream outputStream = File.OpenWrite(input.OutputFile))
                // ascii output?
                using (Stream armoredStream = input.UseArmor ? new ArmoredOutputStream(outputStream) : outputStream)
                using (Stream encryptedOut = GetEncryptionStream(armoredStream, input))
                using (Stream compressedOut = GetCompressionStream(encryptedOut, input))
                {
                    // signature init - if necessary
                    PgpSignatureGenerator signatureGenerator = input.SignWithPrivateKey ? InitPgpSignatureGenerator(compressedOut, input) : null;

                    // writing to configured output
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                    using (Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, new FileInfo(input.InputFile)))
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

                        if (input.SignWithPrivateKey)
                        {
                            signatureGenerator.Generate().Encode(compressedOut);
                        }
                    }
                }

                return new Result
                {
                    FilePath = input.OutputFile
                };
            }
            catch (PgpException e)
            {
                throw;
            }
        }

        /// <summary>
        /// Helper for getting encryption stream
        /// </summary>
        /// <param name="stream">Stream to chain for encryption</param>
        /// <param name="input">Task settings</param>
        /// <returns>Encryption chained stream</returns>
        private static Stream GetEncryptionStream(Stream stream, Input input)
        {
            SymmetricKeyAlgorithmTag algorithmTag = input.EncryptionAlgorithm.ConvertEnum<SymmetricKeyAlgorithmTag>();
            PgpPublicKey publicKey = ReadPublicKey(input.PublicKeyFile);
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(algorithmTag, input.UseIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(publicKey);
            return encryptedDataGenerator.Open(stream, new byte[BUFFER_SIZE]);
        }

        /// <summary>
        /// Gets compression stream if compression is needed, otherwise returns original stream
        /// </summary>
        /// <param name="stream">Source stream</param>
        /// <param name="input">Task input</param>
        /// <returns>Compression chained stream or original source</returns>
        private static Stream GetCompressionStream(Stream stream, Input input)
        {
            if (input.UseArmor)
            {
                CompressionAlgorithmTag compressionTag = input.CompressionType.ConvertEnum<CompressionAlgorithmTag>();
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(compressionTag);
                return compressedDataGenerator.Open(stream);
            }
            return stream;
        }

        /// <summary>
        /// Find first suitable public key for encryption.
        /// </summary>
        /// <param name="publicKeyFile">Path to public key file</param>
        /// <returns>PgpPublicKey from public key file location</returns>
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
        /// <param name="stream">Stream to use for signature initialization</param>
        /// <param name="input">Encryption task input</param>
        /// <returns>PgpSignatureGenerator to be used when signing a file</returns>
        private static PgpSignatureGenerator InitPgpSignatureGenerator(Stream stream, Input input)
        {
            HashAlgorithmTag hashAlgorithm = input.SigningSettings.SignatureHashAlgorithm.ConvertEnum<HashAlgorithmTag>();

            try
            {
                PgpSecretKey secretKey = ReadSecretKey(input.SigningSettings.PrivateKeyFile);
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(input.SigningSettings.PrivateKeyPassword.ToCharArray());

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

                pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(stream);
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
        /// <param name="privateKeyFile">Path to private key file</param>
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