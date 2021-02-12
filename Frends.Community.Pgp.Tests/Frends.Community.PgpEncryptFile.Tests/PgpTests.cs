using NUnit.Framework;
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpEncryptTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private static readonly string SolutionDir = "Frends.Community.PgpEncryptFile.Tests";
        private static readonly string PublicKeyPath = SolutionDir + @"\TestData\pub.asc";
        private static readonly string MessagePath = SolutionDir + @"\TestData\original_message.txt";
        private static readonly string EncryptedMessage = SolutionDir + @"\TestData\encrypted_message.pgp";

        private readonly string _privateKey = @"Frends.Community.PgpEncryptFile.Tests\TestData\privatekey.gpg";
        private readonly string _privateKeyPassword = "veijo666";
        
        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(EncryptedMessage);
        }

        [Test]
        public void EncryptFile()
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
        public void PgpEncryptFile_ShouldSignAndEncryptWithDefaultValues()
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

            StringAssert.StartsWith($@"-----BEGIN PGP MESSAGE-----
Version: BCPG C# v1.8.6.0

hIwDzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }

        [Test(Description = "Encryption algorithm, compression type and signature hash combination tests")]
        public void PgpEncryptFile_ShouldSignAndEncryptWithAllAlgorithmCombinations(
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

        [Test]
        public void PgpEncryptFile_ShouldEncryptWithoutCompression()
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
    }
}
