using System;
using System.IO;
using NUnit.Framework;


namespace Frends.HIT.Pgp.Tests
{
    [TestFixture]
    class PgpVerifyClearTextSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private const string TestData = "TestData";
        private const string TestFolder = "PgpVerifyClearTextSignatureData";
        private static readonly string PublicKeyString =
            Environment.GetEnvironmentVariable("PGPVERIFYCLEARTEXTSIGNATURE_TEST_CERT");
        private static readonly string PublicKeyPath = Path.Combine(TestData, TestFolder, "dontuse-pub.asc");
        private static readonly string Signature = Path.Combine(TestData, TestFolder, "signed_message.txt");
        private static readonly string Output = Path.Combine(TestData, TestFolder, "original_message.txt");

        [Test]
        public void VerifySignOneFileSha1PublicKeyFile()
        {
            PgpVerifyClearTextSignatureInput input = new PgpVerifyClearTextSignatureInput
            {
                InputFile = Signature,
                PublicKeyFile = PublicKeyPath,
                OutputFile = Output,
            };

            PgpVerifyClearTextSignatureResult resultObject = PgpTasks.VerifyFileClearTextSignature(input);
            Assert.That(resultObject.Verified);
        }
        
        [Test]
        public void VerifySignOneFileSha1PublicKeyString()
        {
            PgpVerifyClearTextSignatureInput input = new PgpVerifyClearTextSignatureInput
            {
                InputFile = Signature,
                PublicKey = PublicKeyString,
                OutputFile = Output,
            };

            PgpVerifyClearTextSignatureResult resultObject = PgpTasks.VerifyFileClearTextSignature(input);
            Assert.That(resultObject.Verified);
        }
    }
}
