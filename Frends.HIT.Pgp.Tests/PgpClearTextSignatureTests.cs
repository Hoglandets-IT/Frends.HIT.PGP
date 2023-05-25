using System;
using NUnit.Framework;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;



namespace Frends.HIT.Pgp.Tests
{
    [TestFixture]
    class PgpClearTextSignatureTests
    {
        private const string TestData = "TestData";
        private const string TestFolder = "PgpClearTextSignatureData";
        private static readonly string PrivateKeyPath = Path.Combine(TestData, TestFolder, "dontuse-sec.asc");
        private static readonly string PrivateKeyString =
            Environment.GetEnvironmentVariable("PGPCLEARTEXTSIGNATURE_TEST_CERT");
        private static readonly string SignedMessage = Path.Combine(TestData, TestFolder, "signed_message.txt");
        private static readonly string MessagePath = Path.Combine(TestData, TestFolder, "original_message.txt");
        private static readonly string KeyPassword = "testisalasana1";

        [Test]
        public void SignOneFileSha1PrivateKeyFile()
        {
            PgpClearTextSignatureInput input = new PgpClearTextSignatureInput
            {
                InputFile = MessagePath,
                OutputFile = SignedMessage,
                PrivateKeyFile = PrivateKeyPath,
                Password = KeyPassword,
                HashFunction = PgpClearTextSignatureHashFunctionType.Sha1,
            };

            PgpClearTextSignatureResult resultObject = PgpTasks.ClearTextSignFile(input);

            string result = resultObject.Output;

            string expectedResult = "-----BEGINPGPSIGNEDMESSAGE-----Hash:SHA1\"Secret\"messagethatcontainskanji(漢字)totestutf-8compatibility.-----BEGINPGPSIGNATURE-----Version:BCPGC#v1.8.6.0iQE0BAEBAgAeBQ";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
        
        [Test]
        public void SignOneFileSha1PrivateKeyString()
        {
            PgpClearTextSignatureInput input = new PgpClearTextSignatureInput
            {
                InputFile = MessagePath,
                OutputFile = SignedMessage,
                PrivateKey = PrivateKeyString,
                Password = KeyPassword,
                HashFunction = PgpClearTextSignatureHashFunctionType.Sha1,
            };

            PgpClearTextSignatureResult resultObject = PgpTasks.ClearTextSignFile(input);

            string result = resultObject.Output;

            string expectedResult = "-----BEGINPGPSIGNEDMESSAGE-----Hash:SHA1\"Secret\"messagethatcontainskanji(漢字)totestutf-8compatibility.-----BEGINPGPSIGNATURE-----Version:BCPGC#v1.8.6.0iQE0BAEBAgAeBQ";
            // Rest of the file is random.

            Assert.That(Regex.Replace(result, @"[\s+]", ""), Does.StartWith(Regex.Replace(expectedResult, @"[\s+]", "")));

        }
    }
}
