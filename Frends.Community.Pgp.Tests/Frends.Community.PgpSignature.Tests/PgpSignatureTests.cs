using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace FRENDS.Community.PgpSignature.Tests
{
    [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = "Frends.Community.PgpSignature.Tests";
        private readonly static string private_key_path = _solutionDir + @"\TestData\dontuse-sec.asc";
        private readonly static string signature = _solutionDir + @"\TestData\signature.txt";
        private readonly static string message_path = _solutionDir + @"\TestData\original_message.txt";
        private readonly static string key_password = "testisalasana1";

        [Test]
        public void SignOneFileSha1()
        {
            Input input = new Input
            {
                InputFile = message_path,
                OutputFile = signature,
                PrivateKeyFile = private_key_path,
                Password = key_password,
                HashFunction = HashFunctionType.Sha1,
            };

            Result result_object = PgpSignatureTask.PGPSignFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.1.0kA0DAAIBQmrabh8os";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
