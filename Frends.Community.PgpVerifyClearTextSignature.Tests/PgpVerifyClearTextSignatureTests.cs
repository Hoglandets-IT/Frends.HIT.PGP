using NUnit.Framework;
using System.IO;



namespace FRENDS.Community.PgpVerifyClearTextSignature.Tests
{
    [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        private readonly static string public_key_path = _solutionDir + @"\TestData\dontuse-pub.asc";
        private readonly static string signature = _solutionDir + @"\TestData\signed_message.txt";
        private readonly static string output = _solutionDir + @"\TestData\original_message.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            Input input = new Input
            {
                InputFile = signature,
                PublicKeyFile = public_key_path,
                OutputFile = output,
            };

            Result result_object = PgpVerifyClearTextSignatureTask.PGPVerifyClearTextSignFile(input);
            Assert.That(result_object.Verified);
        }
    }
}
