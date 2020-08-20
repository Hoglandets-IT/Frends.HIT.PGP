using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpClearTextSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = "Frends.Community.PgpClearTextSignature.Tests";
        private readonly static string private_key_path = _solutionDir + @"\TestData\dontuse-sec.asc";
        private readonly static string signed_message = _solutionDir + @"\TestData\signed_message.txt";
        private readonly static string message_path = _solutionDir + @"\TestData\original_message.txt";
        private readonly static string key_password = "testisalasana1";

        [Test]
        public void SignOneFileSha1()
        {
            PgpClearTextSignatureInput input = new PgpClearTextSignatureInput
            {
                InputFile = message_path,
                OutputFile = signed_message,
                PrivateKeyFile = private_key_path,
                Password = key_password,
                HashFunction = PgpClearTextSignatureHashFunctionType.Sha1,
            };

            PgpClearTextSignatureResult result_object = PgpTasks.PGPClearTextSignFile(input);

            string result = File.ReadAllText(result_object.FilePath);

            string expectedResult = "-----BEGINPGPSIGNEDMESSAGE-----Hash:SHA1\"Secret\"messagethatcontainskanji(漢字)totestutf-8compatibility.-----BEGINPGPSIGNATURE-----Version:BCPGC#v1.8.1.0iQE0BAEBAgAeBQ";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
