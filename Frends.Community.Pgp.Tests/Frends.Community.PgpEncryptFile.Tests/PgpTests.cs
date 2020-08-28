using Frends.Community.Pgp;
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
        private readonly static string _solutionDir = "Frends.Community.PgpEncryptFile.Tests";
        private readonly static string public_key_path = _solutionDir + @"\TestData\pub.asc";
        private readonly static string message_path = _solutionDir + @"\TestData\original_message.txt";
        private readonly static string encrypted_message = _solutionDir + @"\TestData\encrypted_message.pgp";

        private readonly string _privateKey = @"Frends.Community.PgpEncryptFile.Tests\TestData\privatekey.gpg";
        private readonly string _privateKeyPassword = "veijo666";
        
        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(encrypted_message);
        }

        [Test]
        public void EncryptFile()
        {
            PgpEncryptInput input = new PgpEncryptInput
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
                UseIntegrityCheck = true,
                UseArmor = true
            };

            PgpEncryptResult result_object = PgpTasks.PgpEncryptFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0hIwDzoB5W4N7pN4B";
             // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }

        [Test]
        public void PgpEncryptFile_ShouldSignAndEncryptWithDefaultValues()
        {
            var input = new PgpEncryptInput
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new PgpEncryptSigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword
                }
            };

            PgpEncryptResult taskResult = PgpTasks.PgpEncryptFile(input);
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
                PgpEncryptSignatureHashAlgorithm.MD2, PgpEncryptSignatureHashAlgorithm.MD5,
                PgpEncryptSignatureHashAlgorithm.RipeMD160, PgpEncryptSignatureHashAlgorithm.Sha1, PgpEncryptSignatureHashAlgorithm.Sha224, PgpEncryptSignatureHashAlgorithm.Sha256,
                PgpEncryptSignatureHashAlgorithm.Sha384, PgpEncryptSignatureHashAlgorithm.Sha512)]
            PgpEncryptSignatureHashAlgorithm signatureHash)
        {
            var input = new PgpEncryptInput
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
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

            PgpEncryptResult taskResult = PgpTasks.PgpEncryptFile(input);
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
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
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

            PgpEncryptResult taskResult = PgpTasks.PgpEncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.6.0\s{4}hI(s|w)DzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
    }
}
