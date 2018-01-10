using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;


namespace FRENDS.Community.PgpDecrypt.Tests
{ 
   [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        private readonly static string private_key_path = _solutionDir + @"\TestData\sec.asc";
        private readonly static string encrypted_message = _solutionDir + @"\TestData\encrypted_message.pgp";
        private readonly static string decrypted_message = _solutionDir + @"\TestData\decrypted_message.pgp";
        private readonly static string key_password = "kissa2";


        [TearDown]
        public void DeleteTmpFile()
        {
            File.Delete(decrypted_message);
        }

        [Test]
        public void DecryptFile()
        {
            Input input = new Input
            {
                InputFile = encrypted_message,
                OutputFile = decrypted_message,
                PrivateKeyFile = private_key_path,
                PassPhrase = key_password,
            };

            Result result_object = FRENDSTaskDecrypt.PgpDecrypt(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "\"Secret\" message that contains kanji (漢字) to test utf-8 compatibility.";

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));


        }
    }
}
