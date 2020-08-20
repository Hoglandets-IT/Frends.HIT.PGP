using NUnit.Framework;
using System.IO;



namespace FRENDS.Community.Pgp.Tests
{
    [TestFixture]
    class PgpVerifySignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = @"Frends.Community.PgpVerifySignature.Tests";
        private readonly static string public_key_path = _solutionDir + @"\TestData\dontuse-pub.asc";
        private readonly static string signature = _solutionDir + @"\TestData\signature.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            var input = new PgpVerifySignatureInput
            {
                InputFile = signature,
                PublicKeyFile = public_key_path,
            };

            PgpVerifySignatureResult result_object = PgpTasks.PGPVerifySignFile(input);

            Assert.That(result_object.Verified);
        }
    }
}
