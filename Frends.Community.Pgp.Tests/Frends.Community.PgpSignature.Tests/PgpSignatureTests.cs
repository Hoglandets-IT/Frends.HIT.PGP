using Frends.Community.Pgp;
using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpSignatureTests
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
            PgpSignatureInput input = new PgpSignatureInput
            {
                InputFile = message_path,
                OutputFile = signature,
                PrivateKeyFile = private_key_path,
                Password = key_password,
                HashFunction = PgpSignatureHashFunctionType.Sha1,
            };

            PgpSignatureResult result_object = PgpTasks.PgpSignFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0kA0DAAIBQmrabh8os";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
