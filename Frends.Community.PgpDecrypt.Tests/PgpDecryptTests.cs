using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;


namespace FRENDS.Community.PgpDecrypt.Tests
{ 
   [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly string private_key_path = @"Frends.Community.PgpDecrypt.Tests\TestData\sec.asc";
        private readonly string encrypted_message = @"Frends.Community.PgpDecrypt.Tests\TestData\encrypted_message.pgp";
        private readonly string decrypted_message = @"Frends.Community.PgpDecrypt.Tests\TestData\decrypted_message.pgp";
        private readonly string key_password = "kissa2";


        [TearDown]
        public void AlwaysTrue2()
        {
            File.Delete(encrypted_message);
        }

        [Test]
        public void AlwaysTrue()
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
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));


        }
    }
}
