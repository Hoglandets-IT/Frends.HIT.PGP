using NUnit.Framework;


namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpVerifyClearTextSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private static readonly string _solutionDir = "Frends.Community.PgpVerifyClearTextSignature.Tests";
        private static readonly string _publicKeyPath = _solutionDir + @"\TestData\dontuse-pub.asc";
        private static readonly string _signature = _solutionDir + @"\TestData\signed_message.txt";
        private static readonly string _output = _solutionDir + @"\TestData\original_message.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            PgpVerifyClearTextSignatureInput input = new PgpVerifyClearTextSignatureInput
            {
                InputFile = _signature,
                PublicKeyFile = _publicKeyPath,
                OutputFile = _output,
            };

            PgpVerifyClearTextSignatureResult resultObject = PgpTasks.VerifyFileClearTextSignature(input);
            Assert.That(resultObject.Verified);
        }
    }
}
