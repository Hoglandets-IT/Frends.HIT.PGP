using System;
using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;


namespace Frends.HIT.Pgp.Tests
{ 
   [TestFixture]
    class PgpDecryptTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        //private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        //AppDomain.CurrentDomain.SetupInformation.ApplicationBase
        private const string TestData = "TestData";
        private const string TestFolder = "PgpDecryptData";
        private static readonly string PrivateKeyString =
            Environment.GetEnvironmentVariable("PGPDECRYPT_TEST_CERT");
        private static readonly string PrivateKeyPath = Path.Combine(TestData, TestFolder, "sec.asc");
        private static readonly string EncryptedMessage = Path.Combine(TestData, TestFolder, "encrypted_message.pgp");
        private static readonly string DecryptedMessage = Path.Combine(TestData, TestFolder, "decrypted_message.pgp");
        private static readonly string KeyPassword = "kissa2";


        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(DecryptedMessage);
        }

        [Test]
        public void DecryptFilePrivateKeyFile()
        {
            PgpDecryptInput input = new PgpDecryptInput
            {
                InputFile = EncryptedMessage,
                OutputFile = DecryptedMessage,
                PrivateKeyFile = PrivateKeyPath,
                PassPhrase = KeyPassword,
            };

            PgpDecryptResult resultObject = PgpTasks.DecryptFile(input);

            string result = resultObject.Output;

            string expectedResult = "\"Secret\" message that contains kanji (漢字) to test utf-8 compatibility.";

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }
        
        [Test]
        public void DecryptFilePrivateKeyString()
        {
            PgpDecryptInput input = new PgpDecryptInput
            {
                InputFile = EncryptedMessage,
                OutputFile = DecryptedMessage,
                PrivateKey = PrivateKeyString,
                PassPhrase = KeyPassword,
            };

            PgpDecryptResult resultObject = PgpTasks.DecryptFile(input);

            string result = File.ReadAllText(resultObject.Output);

            string expectedResult = "\"Secret\" message that contains kanji (漢字) to test utf-8 compatibility.";

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));
        }
    }
}
