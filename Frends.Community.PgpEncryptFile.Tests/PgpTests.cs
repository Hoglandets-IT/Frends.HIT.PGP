using NUnit.Framework;
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Frends.Community.PgpEncrypt.Tests
{
    [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        private readonly static string public_key_path = _solutionDir + @"\TestData\pub.asc";
        private readonly static string message_path = _solutionDir + @"\TestData\original_message.txt";
        private readonly static string encrypted_message = _solutionDir + @"\TestData\encrypted_message.pgp";

        private readonly string _privateKey = AppDomain.CurrentDomain.BaseDirectory + @"\TestData\privatekey.gpg";
        private readonly string _privateKeyPassword = "veijo666";
        
        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(encrypted_message);
        }

        [Test]
        public void EncryptFile()
        {
            Input input = new Input
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
                UseIntegrityCheck = true,
                UseArmor = true
            };

            Result result_object = PgpEncryptFileTask.PgpEncryptFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.1.0hIwDzoB5W4N7pN4B";
             // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }

        [Test]
        public void PgpEncryptFile_ShouldSignAndEncryptWithDefaultValues()
        {
            var input = new Input
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new SigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword
                }
            };

            Result taskResult = PgpEncryptFileTask.PgpEncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);

            StringAssert.StartsWith($@"-----BEGIN PGP MESSAGE-----
Version: BCPG C# v1.8.1.0

hIwDzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }

        [Test(Description = "Encryption algorithm, compression type and signature hash combination tests")]
        public void PgpEncryptFile_ShouldSignAndEncryptWithAllAlgorithmCombinations(
            [Values(
                EncryptionAlgorithm.Aes128, EncryptionAlgorithm.Aes192, EncryptionAlgorithm.Aes256, EncryptionAlgorithm.Blowfish,
                EncryptionAlgorithm.Camellia128, EncryptionAlgorithm.Camellia192, EncryptionAlgorithm.Camellia256, EncryptionAlgorithm.Cast5,
                EncryptionAlgorithm.Des, EncryptionAlgorithm.Idea, EncryptionAlgorithm.TripleDes, EncryptionAlgorithm.Twofish
            )]
            EncryptionAlgorithm encryptionAlgorithm,
            [Values(CompressionType.BZip2, CompressionType.Uncompressed, CompressionType.Zip, CompressionType.ZLib)]
            CompressionType compressionType,
            [Values(
                SignatureHashAlgorithm.MD2, SignatureHashAlgorithm.MD5,
                SignatureHashAlgorithm.RipeMD160, SignatureHashAlgorithm.Sha1, SignatureHashAlgorithm.Sha224, SignatureHashAlgorithm.Sha256,
                SignatureHashAlgorithm.Sha384, SignatureHashAlgorithm.Sha512)]
            SignatureHashAlgorithm signatureHash)
        {
            var input = new Input
            {
                InputFile = message_path,
                OutputFile = encrypted_message,
                PublicKeyFile = public_key_path,
                EncryptionAlgorithm = encryptionAlgorithm,
                CompressionType = compressionType,
                UseArmor = true,
                UseIntegrityCheck = true,
                SignWithPrivateKey = true,
                SigningSettings = new SigningSettings
                {
                    PrivateKeyFile = _privateKey,
                    PrivateKeyPassword = _privateKeyPassword,
                    SignatureHashAlgorithm = signatureHash
                }
            };

            Result taskResult = PgpEncryptFileTask.PgpEncryptFile(input);
            string textResult = File.ReadAllText(taskResult.FilePath);
            
            // result has to start with pgp prefix, version comment and almost static 16 chars
            StringAssert.IsMatch(@"^-----BEGIN PGP MESSAGE-----\s{2}Version: BCPG C# v1.8.1.0\s{4}hI(s|w)DzoB5W4N7pN4B", textResult);
            StringAssert.EndsWith($"-----END PGP MESSAGE-----{Environment.NewLine}", textResult);
        }
    }
}
