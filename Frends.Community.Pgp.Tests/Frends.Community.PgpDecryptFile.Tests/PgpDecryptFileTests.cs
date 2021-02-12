using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;


namespace Frends.Community.Pgp.Tests
{ 
   [TestFixture]
    class PgpDecryptTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        //private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        //AppDomain.CurrentDomain.SetupInformation.ApplicationBase
        private static readonly string SolutionDir = "Frends.Community.PgpDecryptFile.Tests";
        private static readonly string PrivateKeyPath = SolutionDir + @"\TestData\sec.asc";
        private static readonly string EncryptedMessage = SolutionDir + @"\TestData\encrypted_message.pgp";
        private static readonly string DecryptedMessage = SolutionDir + @"\TestData\decrypted_message.pgp";
        private static readonly string KeyPassword = "kissa2";


        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(DecryptedMessage);
        }

        [Test]
        public void DecryptFile()
        {
            PgpDecryptInput input = new PgpDecryptInput
            {
                InputFile = EncryptedMessage,
                OutputFile = DecryptedMessage,
                PrivateKeyFile = PrivateKeyPath,
                PassPhrase = KeyPassword,
            };

            PgpDecryptResult resultObject = PgpTasks.DecryptFile(input);

            string result = File.ReadAllText(resultObject.FilePath);

            string expectedResult = "\"Secret\" message that contains kanji (漢字) to test utf-8 compatibility.";

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));


        }
    }
}
