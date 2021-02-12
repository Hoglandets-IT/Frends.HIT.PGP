using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;



namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private static readonly string SolutionDir = "Frends.Community.PgpSignature.Tests";
        private static readonly string PrivateKeyPath = SolutionDir + @"\TestData\dontuse-sec.asc";
        private static readonly string Signature = SolutionDir + @"\TestData\signature.txt";
        private static readonly string MessagePath = SolutionDir + @"\TestData\original_message.txt";
        private static readonly string KeyPassword = "testisalasana1";

        [Test]
        public void SignOneFileSha1()
        {
            PgpSignatureInput input = new PgpSignatureInput
            {
                InputFile = MessagePath,
                OutputFile = Signature,
                PrivateKeyFile = PrivateKeyPath,
                Password = KeyPassword,
                HashFunction = PgpSignatureHashFunctionType.Sha1,
            };

            PgpSignatureResult resultObject = PgpTasks.SignFile(input);

            string result = File.ReadAllText(resultObject.FilePath);

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0kA0DAAIBQmrabh8os";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
