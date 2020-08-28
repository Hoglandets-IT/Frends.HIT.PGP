using NUnit.Framework;
using System.IO;



namespace Frends.Community.Pgp.Tests
{
    [TestFixture]
    class PgpVerifyClearTextSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private readonly static string _solutionDir = "Frends.Community.PgpVerifyClearTextSignature.Tests";
        private readonly static string public_key_path = _solutionDir + @"\TestData\dontuse-pub.asc";
        private readonly static string signature = _solutionDir + @"\TestData\signed_message.txt";
        private readonly static string output = _solutionDir + @"\TestData\original_message.txt";

        [Test]
        public void VerifySignOneFileSha1()
        {
            PgpVerifyClearTextSignatureInput input = new PgpVerifyClearTextSignatureInput
            {
                InputFile = signature,
                PublicKeyFile = public_key_path,
                OutputFile = output,
            };

            PgpVerifyClearTextSignatureResult result_object = PgpTasks.PgpVerifyFileClearTextSignature(input);
            Assert.That(result_object.Verified);
        }
    }
}
