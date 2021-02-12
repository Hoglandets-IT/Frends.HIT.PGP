using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpClearTextSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private static readonly string SolutionDir = "Frends.Community.PgpClearTextSignature.Tests";
        private static readonly string PrivateKeyPath = SolutionDir + @"\TestData\dontuse-sec.asc";
        private static readonly string SignedMessage = SolutionDir + @"\TestData\signed_message.txt";
        private static readonly string MessagePath = SolutionDir + @"\TestData\original_message.txt";
        private static readonly string KeyPassword = "testisalasana1";

        [Test]
        public void SignOneFileSha1()
        {
            PgpClearTextSignatureInput input = new PgpClearTextSignatureInput
            {
                InputFile = MessagePath,
                OutputFile = SignedMessage,
                PrivateKeyFile = PrivateKeyPath,
                Password = KeyPassword,
                HashFunction = PgpClearTextSignatureHashFunctionType.Sha1,
            };

            PgpClearTextSignatureResult resultObject = PgpTasks.ClearTextSignFile(input);

            string result = File.ReadAllText(resultObject.FilePath);

            string expectedResult = "-----BEGINPGPSIGNEDMESSAGE-----Hash:SHA1\"Secret\"messagethatcontainskanji(漢字)totestutf-8compatibility.-----BEGINPGPSIGNATURE-----Version:BCPGC#v1.8.6.0iQE0BAEBAgAeBQ";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
