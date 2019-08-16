using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace FRENDS.Community.PgpClearTextSignature.Tests
{
    [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        private readonly static string private_key_path = _solutionDir + @"\TestData\dontuse-sec.asc";
        private readonly static string signed_message = _solutionDir + @"\TestData\signed_message.txt";
        private readonly static string message_path = _solutionDir + @"\TestData\original_message.txt";
        private readonly static string key_password = "testisalasana1";

        [Test]
        public void SignOneFileSha1()
        {
            Input input = new Input
            {
                InputFile = message_path,
                OutputFile = signed_message,
                PrivateKeyFile = private_key_path,
                Password = key_password,
                HashFunction = HashFunctionType.Sha1,
            };

            Result result_object = PgpClearTextSignatureTask.PGPClearTextSignFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPSIGNEDMESSAGE-----Hash:SHA1\"Secret\"messagethatcontainskanji(漢字)totestutf-8compatibility.-----BEGINPGPSIGNATURE-----Version:BCPGC#v1.8.1.0iQE0BAEBAgAeBQ";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
