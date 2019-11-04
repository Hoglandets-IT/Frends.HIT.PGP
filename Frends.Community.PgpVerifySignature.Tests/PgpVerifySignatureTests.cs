using NUnit.Framework;
using System.IO;



namespace FRENDS.Community.PgpVerifySignature.Tests
{
    [TestFixture]
    class PgpTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = Path.GetDirectoryName(Path.GetDirectoryName(TestContext.CurrentContext.TestDirectory));
        private readonly static string public_key_path = _solutionDir + @"\TestData\dontuse-pub.asc";
        private readonly static string signature = _solutionDir + @"\TestData\signature.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            Input input = new Input
            {
                InputFile = signature,
                PublicKeyFile = public_key_path,
            };

            Result result_object = PgpVerifySignatureTask.PGPVerifySignFile(input);

            Assert.That(result_object.Verified);
        }
    }
}
