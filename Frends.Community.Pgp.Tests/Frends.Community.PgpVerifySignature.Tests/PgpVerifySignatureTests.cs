using NUnit.Framework;


namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpVerifySignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private static readonly string _solutionDir = @"Frends.Community.PgpVerifySignature.Tests";
        private static readonly string _publicKeyPath = _solutionDir + @"\TestData\dontuse-pub.asc";
        private static readonly string _signature = _solutionDir + @"\TestData\signature.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            var input = new PgpVerifySignatureInput
            {
                InputFile = _signature,
                PublicKeyFile = _publicKeyPath,
            };

            PgpVerifySignatureResult resultObject = PgpTasks.VerifyFileSignature(input);

            Assert.That(resultObject.Verified);
        }
    }
}
