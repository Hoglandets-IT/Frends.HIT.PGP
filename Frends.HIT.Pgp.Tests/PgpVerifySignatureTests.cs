using System;
using System.IO;
using NUnit.Framework;


namespace Frends.HIT.Pgp.Tests
{
    [TestFixture]
    class PgpVerifySignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private const string TestData = "TestData";
        private const string TestFolder = "PgpVerifySignatureData";
        private static readonly string PublicKeyString =
            Environment.GetEnvironmentVariable("PGPVERIFYSIGNATURE_TEST_CERT");
        private static readonly string PublicKeyPath = Path.Combine(TestData, TestFolder, "dontuse-pub.asc");
        private static readonly string Signature = Path.Combine(TestData, TestFolder, "signature.txt");
        private string _userInputString;

        [SetUp]
        public void SetUp()
        {
            _userInputString = File.ReadAllText(Signature);
        }

        [Test]
        public void VerifySignOneFileSha1PublicKeyFile()
        {
            var input = new PgpVerifySignatureInput
            {
                InputFile = Signature,
                PublicKeyFile = PublicKeyPath,
            };

            var resultObject = PgpTasks.VerifyFileSignature(input);

            Assert.That(resultObject.Verified);
        }
        
        [Test]
        public void VerifySignOneFileSha1PublicKeyFileAndUserInput()
        {
            var input = new PgpVerifySignatureInput
            {
                InputString = _userInputString,
                PublicKeyFile = PublicKeyPath,
            };

            var resultObject = PgpTasks.VerifyFileSignature(input);

            Assert.That(resultObject.Verified);
        }
        
        [Test]
        public void VerifySignOneFileSha1PublicKeyString()
        {
            var input = new PgpVerifySignatureInput
            {
                InputFile = Signature,
                PublicKey = PublicKeyString,
            };

            var resultObject = PgpTasks.VerifyFileSignature(input);

            Assert.That(resultObject.Verified);
        }
        
        [Test]
        public void VerifySignOneFileSha1PublicKeyStringAndUserInput()
        {
            var input = new PgpVerifySignatureInput
            {
                InputFile = Signature,
                PublicKey = PublicKeyString,
            };

            var resultObject = PgpTasks.VerifyFileSignature(input);

            Assert.That(resultObject.Verified);
        }
    }
}
