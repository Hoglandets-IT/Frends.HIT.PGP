using NUnit.Framework;
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Frends.HIT.Pgp.Tests
{
    [TestFixture]
    class PgpEncryptTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private const string TestData = "TestData";
        private const string TestFolder = "PgpEncryptData";
        private static readonly string PublicKeyString =
            Environment.GetEnvironmentVariable("PGPENCRYPT_TEST_CERT_PUB");
        private static readonly string PrivateKeyString =
            Environment.GetEnvironmentVariable("PGPENCRYPT_TEST_CERT_SEC");
        private static readonly string PublicKeyPath = Path.Combine(TestData, TestFolder, "pub.asc");
        private static readonly string MessagePath = Path.Combine(TestData, TestFolder, "original_message.txt");
        private static readonly string EncryptedMessage = Path.Combine(TestData, TestFolder, "encrypted_message.pgp");

        private readonly string _privateKey = Path.Combine(TestData, TestFolder, "privatekey.gpg");
        private readonly string _privateKeyPassword = "veijo666";
        
        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(EncryptedMessage);
        }

        [Test]
        public void EncryptFilePublicKeyFile()
        {
            PgpEncryptInput input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKeyFile = PublicKeyPath,
                UseIntegrityCheck = true,
                UseArmor = true
            };

            PgpEncryptResult resultObject = PgpTasks.EncryptFile(input);

            string result = File.ReadAllText(resultObject.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0hIwDzoB5W4N7pN4B";
             // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }
        
        [Test]
        public void EncryptFilePublicKeyString()
        {
            PgpEncryptInput input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKey = PublicKeyString,
                UseIntegrityCheck = true,
                UseArmor = true
            };

            PgpEncryptResult resultObject = PgpTasks.EncryptFile(input);

            string result = File.ReadAllText(resultObject.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0hIwDzoB5W4N7pN4B";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }

        [Test]
        public void PgpEncryptFile_ShouldSignAndEncryptWithDefaultValuesPublicKeyFile()
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKeyFile = PublicKeyPath,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            StringAssert.StartsWith($@"-----BEGIN PGP MESSAGE-----", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
        
        [Test]
        public void PgpEncryptFile_ShouldSignAndEncryptWithDefaultValuesPublicKeyString()
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKey = PublicKeyString,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKey = PrivateKeyString,
                    PrivateKeyPassword = _privateKeyPassword
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            StringAssert.StartsWith($@"-----BEGIN PGP MESSAGE-----", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }

        [Test(Description = "Encryption algorithm, compression type and signature hash combination tests with Public key file")]
        public void PgpEncryptFile_ShouldSignAndEncryptWithAllAlgorithmCombinationsPublicKeyFile(
            [Values(
                PgpEncryptEncryptionAlgorithm.Aes128, PgpEncryptEncryptionAlgorithm.Aes192, PgpEncryptEncryptionAlgorithm.Aes256, PgpEncryptEncryptionAlgorithm.Blowfish,
                PgpEncryptEncryptionAlgorithm.Camellia128, PgpEncryptEncryptionAlgorithm.Camellia192, PgpEncryptEncryptionAlgorithm.Camellia256, PgpEncryptEncryptionAlgorithm.Cast5,
                PgpEncryptEncryptionAlgorithm.Des, PgpEncryptEncryptionAlgorithm.Idea, PgpEncryptEncryptionAlgorithm.TripleDes, PgpEncryptEncryptionAlgorithm.Twofish
            )]
            PgpEncryptEncryptionAlgorithm encryptionAlgorithm,
            [Values(PgpEncryptCompressionType.BZip2, PgpEncryptCompressionType.Uncompressed, PgpEncryptCompressionType.Zip, PgpEncryptCompressionType.ZLib)]
            PgpEncryptCompressionType compressionType,
            [Values(
                PgpEncryptSignatureHashAlgorithm.Md2, PgpEncryptSignatureHashAlgorithm.Md5,
                PgpEncryptSignatureHashAlgorithm.RipeMd160, PgpEncryptSignatureHashAlgorithm.Sha1, PgpEncryptSignatureHashAlgorithm.Sha224, PgpEncryptSignatureHashAlgorithm.Sha256,
                PgpEncryptSignatureHashAlgorithm.Sha384, PgpEncryptSignatureHashAlgorithm.Sha512)]
            PgpEncryptSignatureHashAlgorithm signatureHash)
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKeyFile = PublicKeyPath,
                EncryptionAlgorithm = encryptionAlgorithm,
                UseCompression = true,
                CompressionType = compressionType,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword,
                    SignatureHashAlgorithm = signatureHash
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);
            
            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.6.0\s{4}hI(s|w)DzoB5W4N7pN4B*", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
        
        [Test(Description = "Encryption algorithm, compression type and signature hash combination tests with Public key string")]
        public void PgpEncryptFile_ShouldSignAndEncryptWithAllAlgorithmCombinationsPublicKeyString(
            [Values(
                PgpEncryptEncryptionAlgorithm.Aes128, PgpEncryptEncryptionAlgorithm.Aes192, PgpEncryptEncryptionAlgorithm.Aes256, PgpEncryptEncryptionAlgorithm.Blowfish,
                PgpEncryptEncryptionAlgorithm.Camellia128, PgpEncryptEncryptionAlgorithm.Camellia192, PgpEncryptEncryptionAlgorithm.Camellia256, PgpEncryptEncryptionAlgorithm.Cast5,
                PgpEncryptEncryptionAlgorithm.Des, PgpEncryptEncryptionAlgorithm.Idea, PgpEncryptEncryptionAlgorithm.TripleDes, PgpEncryptEncryptionAlgorithm.Twofish
            )]
            PgpEncryptEncryptionAlgorithm encryptionAlgorithm,
            [Values(PgpEncryptCompressionType.BZip2, PgpEncryptCompressionType.Uncompressed, PgpEncryptCompressionType.Zip, PgpEncryptCompressionType.ZLib)]
            PgpEncryptCompressionType compressionType,
            [Values(
                PgpEncryptSignatureHashAlgorithm.Md2, PgpEncryptSignatureHashAlgorithm.Md5,
                PgpEncryptSignatureHashAlgorithm.RipeMd160, PgpEncryptSignatureHashAlgorithm.Sha1, PgpEncryptSignatureHashAlgorithm.Sha224, PgpEncryptSignatureHashAlgorithm.Sha256,
                PgpEncryptSignatureHashAlgorithm.Sha384, PgpEncryptSignatureHashAlgorithm.Sha512)]
            PgpEncryptSignatureHashAlgorithm signatureHash)
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKey = PublicKeyString,
                EncryptionAlgorithm = encryptionAlgorithm,
                UseCompression = true,
                CompressionType = compressionType,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKey = PrivateKeyString,
                    PrivateKeyPassword = _privateKeyPassword,
                    SignatureHashAlgorithm = signatureHash
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);
            
            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.6.0\s{4}hI(s|w)DzoB5W4N7pN4B*", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }

        [Test]
        public void PgpEncryptFile_ShouldEncryptWithoutCompressionPublicKeyFile()
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKeyFile = PublicKeyPath,
                EncryptionAlgorithm = PgpEncryptEncryptionAlgorithm.Cast5,
                UseArmor = true,
                UseIntegrityCheck = true,
                UseCompression = false,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword,
                    SignatureHashAlgorithm = PgpEncryptSignatureHashAlgorithm.Sha256
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.6.0\s{4}hI(s|w)DzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
        
        [Test]
        public void PgpEncryptFile_ShouldEncryptWithoutCompressionPublicKeyString()
        {
            var input = new PgpEncryptInput
            {
                InputFile = MessagePath,
                OutputFile = EncryptedMessage,
                PublicKey = PublicKeyString,
                EncryptionAlgorithm = PgpEncryptEncryptionAlgorithm.Cast5,
                UseArmor = true,
                UseIntegrityCheck = true,
                UseCompression = false,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKey = PrivateKeyString,
                    PrivateKeyPassword = _privateKeyPassword,
                    SignatureHashAlgorithm = PgpEncryptSignatureHashAlgorithm.Sha256
                }
            };

            PgpEncryptResult taskResult = PgpTasks.EncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.6.0\s{4}hI(s|w)DzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
    }
}
