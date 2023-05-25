using System;
using NUnit.Framework;
using System.IO;
using System.Text.RegularExpressions;
using Assert = NUnit.Framework.Assert;

namespace Frends.HIT.Pgp.Tests
{
    [TestFixture]
    class PgpSignatureTests
    {
        // following keys should not be used on anything except testing as both private key and password are on public GitHub repository 
        private const string TestData = "TestData";
        private const string TestFolder = "PgpSignatureData";
        private static readonly string PrivateKeyString =
            Environment.GetEnvironmentVariable("PGPSIGNATURE_TEST_CERT");
        private static readonly string PrivateKeyPath = Path.Combine(TestData, TestFolder, "dontuse-sec.asc");
        private static readonly string Signature = Path.Combine(TestData, TestFolder, "signature.txt");
        private static readonly string MessagePath = Path.Combine(TestData, TestFolder, "original_message.txt");
        private static readonly string KeyPassword = "testisalasana1";
        private static string _messageString;

        [SetUp]
        public void Setup()
        {
            _messageString = File.ReadAllText(MessagePath);
        }

        [Test]
        public void SignOneFileSha1PrivateKeyFile()
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

            string result = resultObject.Output;

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0kA0DAAIBQmrabh8os";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
        
        [Test]
        public void SignOneFileSha1PrivateKeyString()
        {
            TestContext.WriteLine($"privateKeystring: {string.IsNullOrEmpty(PrivateKeyString)}");
            PgpSignatureInput input = new PgpSignatureInput
            {
                InputString = _messageString,
                OutputFile = Signature,
                PrivateKey = PrivateKeyString,
                Password = KeyPassword,
                HashFunction = PgpSignatureHashFunctionType.Sha1,
            };

            PgpSignatureResult resultObject = PgpTasks.SignFile(input);

            string result = resultObject.Output;

            string expectedResult = "-----BEGINPGPMESSAGE-----Version:BCPGC#v1.8.6.0kA0DAAIBQmrabh8os";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
