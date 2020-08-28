using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using System.Collections;
using Frends.Community.Pgp;
using Org.BouncyCastle.Utilities.IO;
using System.Text;

#pragma warning disable 1591

namespace Frends.Community.Pgp
{

    public class PgpTasks
    {
        internal const int PGP_ENCRYPT_BUFFER_SIZE = 1 << 16;


        #region PgpDecryptFile

        /// <summary>
        /// Decrypt the file using the private key.
        /// </summary>
        public static PgpDecryptResult PgpDecryptFile(PgpDecryptInput input)
        {
            if (!File.Exists(input.InputFile))
                throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", input.InputFile));

            if (!File.Exists(input.PrivateKeyFile))
                throw new FileNotFoundException(string.Format("Private Key File [{0}] not found.", input.PrivateKeyFile));

            if (string.IsNullOrEmpty(input.OutputFile))
                throw new ArgumentNullException("Invalid Output file path.");

            using (Stream inputStream = File.OpenRead(input.InputFile))
            {
                using (Stream keyIn = File.OpenRead(input.PrivateKeyFile))
                {
                    Decrypt(inputStream, keyIn, input.PassPhrase, input.OutputFile);
                }
            }
            PgpDecryptResult ret = new PgpDecryptResult
            {
                FilePath = input.OutputFile
            };

            return ret;
        }





        internal static bool Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
        {
            PgpObjectFactory pgpF = null;
            PgpEncryptedDataList enc = null;
            PgpObject o = null;
            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            PgpSecretKeyRingBundle pgpSec = null;

            pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            if (pgpF != null)
                o = pgpF.NextPgpObject();

            // the first object might be a PGP marker packet.
            if (o is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)o;
            else
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

            // decrypt
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                sKey = Services.FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (sKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (sKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;

            using (Stream clear = pbe.GetDataStream(sKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    using (Stream output = File.Create(outputFile))
                    {
                        Stream unc = Ld.GetInputStream();
                        Streams.PipeAll(unc, output);
                    }
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    using (Stream output = File.Create(outputFile))
                    {
                        Stream unc = Ld.GetInputStream();
                        Streams.PipeAll(unc, output);
                    }
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                using (Stream fOut = File.Create(outputFile))
                {
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                }
            }
            else if (message is PgpOnePassSignatureList)
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            else
                throw new PgpException("Message is not a simple encrypted file - type unknown.");

            return true;
        }

        #endregion

        #region PgpEncryptFile

        /// <summary>
        /// Encrypts a file using public key.
        /// If needed, the file can also be signed with private key, in this case, the order is sign and encrypt.
        /// See https://github.com/CommunityHiQ/Frends.Community.PgpEncryptFile
        /// </summary>
        /// <param name="input">Task input</param>
        /// <returns>Returns: Object {string FilePath}</returns>
        public static PgpEncryptResult PgpEncryptFile(PgpEncryptInput input)
        {
            // source file to encrypt
            FileInfo inputFile = new FileInfo(input.InputFile);

            if (!inputFile.Exists)
                throw new ArgumentException("File to encrypt does not exists", "input.InputFile");
            {
                // destination file
                using (Stream outputStream = File.OpenWrite(input.OutputFile))
                // ascii output?
                using (Stream armoredStream = input.UseArmor ? new ArmoredOutputStream(outputStream) : outputStream)
                using (Stream encryptedOut = Services.GetEncryptionStream(armoredStream, input))
                using (Stream compressedOut = Services.GetCompressionStream(encryptedOut, input))
                {
                    // signature init - if necessary
                    PgpSignatureGenerator signatureGenerator = input.SignWithPrivateKey ? Services.InitPgpSignatureGenerator(compressedOut, input) : null;

                    // writing to configured output
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                    FileInfo file = new FileInfo(input.InputFile);
                    using (Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file.Name, file.Length, DateTime.Now))
                    using (FileStream inputStream = inputFile.OpenRead())
                    {
                        byte[] buf = new byte[PGP_ENCRYPT_BUFFER_SIZE];
                        int len;

                        while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
                        {
                            literalOut.Write(buf, 0, len);
                            if (input.SignWithPrivateKey)
                            {
                                signatureGenerator.Update(buf, 0, len);
                            }
                        }

                        if (input.SignWithPrivateKey)
                        {
                            signatureGenerator.Generate().Encode(compressedOut);
                        }
                    }
                }

                return new PgpEncryptResult
                {
                    FilePath = input.OutputFile
                };
            }

        }

        #endregion

        #region PgpSignFile

        /// <summary>
        /// Sign a file with PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpSignature Returns: Object {string FilePath}
        /// </summary>
        public static PgpSignatureResult PgpSignFile(PgpSignatureInput input)
        {
            HashAlgorithmTag digest = input.HashFunction.ConvertEnum<HashAlgorithmTag>();

            using (var privateKeyStream = File.OpenRead(input.PrivateKeyFile))
            {
                PgpSecretKey pgpSecKey = Services.PgpSignatureReadSecretKey(privateKeyStream);
                PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(input.Password.ToCharArray());
                PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
                PgpSignatureSubpacketGenerator signatureSubpacketGenerator = new PgpSignatureSubpacketGenerator();

                signatureGenerator.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.BinaryDocument, pgpPrivKey);

                IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
                if (enumerator.MoveNext())
                {
                    signatureSubpacketGenerator.SetSignerUserId(false, (string)enumerator.Current);
                    signatureGenerator.SetHashedSubpackets(signatureSubpacketGenerator.Generate());
                }

                using (var outputStream = File.Create(input.OutputFile))
                {
                    ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
                    // armoredOutputStream.SetHeader("Version", "BCPG C# v1.8.1.0");
                    BcpgOutputStream bcbgOutputStream = new BcpgOutputStream(armoredOutputStream);
                    signatureGenerator.GenerateOnePassVersion(false).Encode(bcbgOutputStream);

                    FileInfo file = new FileInfo(input.InputFile);
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                    Stream literalDataOut = literalDataGenerator.Open(bcbgOutputStream, PgpLiteralData.Binary, file.Name, file.Length, DateTime.Now);
                    using (var fileIn = file.OpenRead())
                    {
                        int ch;

                        while ((ch = fileIn.ReadByte()) >= 0)
                        {
                            literalDataOut.WriteByte((byte)ch);
                            signatureGenerator.Update((byte)ch);
                        }

                        fileIn.Close();
                        literalDataGenerator.Close();
                        signatureGenerator.Generate().Encode(bcbgOutputStream);
                        armoredOutputStream.Close();
                        outputStream.Close();

                        PgpSignatureResult ret = new PgpSignatureResult
                        {
                            FilePath = input.OutputFile
                        };
                        return ret;
                    }
                }
            }
        }

        #endregion

        #region PgpVerifyFileSignature
        /// <summary>
        /// Verifies a PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifySignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static PgpVerifySignatureResult PgpVerifyFileSignature(PgpVerifySignatureInput input)
        {

            using (var inputStream = PgpUtilities.GetDecoderStream(File.OpenRead(input.InputFile)))
            using (var keyStream = PgpUtilities.GetDecoderStream(File.OpenRead(input.PublicKeyFile)))
            {
                PgpObjectFactory pgpFact = new PgpObjectFactory(inputStream);
                PgpOnePassSignatureList signatureList = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
                PgpOnePassSignature onePassSignature = signatureList[0];

                PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();
                Stream dataIn = p2.GetInputStream();
                PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(keyStream);
                PgpPublicKey key = pgpRing.GetPublicKey(onePassSignature.KeyId);

                string outputPath;
                if (string.IsNullOrWhiteSpace(input.OutputFolder))
                {
                    outputPath = Path.Combine(Path.GetDirectoryName(input.InputFile), p2.FileName);
                }
                else
                {
                    outputPath = Path.Combine(input.OutputFolder, p2.FileName);
                }
                using (var outputStream = File.Create(outputPath))
                {
                    onePassSignature.InitVerify(key);

                    int ch;
                    while ((ch = dataIn.ReadByte()) >= 0)
                    {
                        onePassSignature.Update((byte)ch);
                        outputStream.WriteByte((byte)ch);
                    }
                    outputStream.Close();
                }

                bool verified;
                // Will throw Exception if file is altered
                try
                {
                    PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                    PgpSignature firstSig = p3[0];
                    verified = onePassSignature.Verify(firstSig);
                }
                catch (Exception)
                {
                    PgpVerifySignatureResult retError = new PgpVerifySignatureResult
                    {
                        FilePath = input.OutputFolder,
                        Verified = false
                    };

                    return retError;
                }

                PgpVerifySignatureResult ret = new PgpVerifySignatureResult
                {
                    FilePath = outputPath,
                    Verified = verified
                };

                return ret;
            }
        }

        #endregion

        #region PgpClearTextSignFile
        /// <summary>
        /// Create a file with PGP clear text signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpClearTextSignature Returns: Object {string FilePath}
        /// </summary>
        public static PgpClearTextSignatureResult PgpClearTextSignFile(PgpClearTextSignatureInput input)
        {
            HashAlgorithmTag digest;
            if (input.HashFunction == PgpClearTextSignatureHashFunctionType.MD5)
            {
                digest = HashAlgorithmTag.MD5;
            }
            else if (input.HashFunction == PgpClearTextSignatureHashFunctionType.RipeMD160)
            {
                digest = HashAlgorithmTag.RipeMD160;
            }
            else if (input.HashFunction == PgpClearTextSignatureHashFunctionType.Sha1)
            {
                digest = HashAlgorithmTag.Sha1;
            }
            else if (input.HashFunction == PgpClearTextSignatureHashFunctionType.Sha224)
            {
                digest = HashAlgorithmTag.Sha224;
            }
            else if (input.HashFunction == PgpClearTextSignatureHashFunctionType.Sha384)
            {
                digest = HashAlgorithmTag.Sha384;
            }
            else if (input.HashFunction == PgpClearTextSignatureHashFunctionType.Sha512)
            {
                digest = HashAlgorithmTag.Sha512;
            }
            else
            {
                digest = HashAlgorithmTag.Sha256;
            }

            Stream privateKeyStream = File.OpenRead(input.PrivateKeyFile);

            PgpSecretKey pgpSecKey = Services.ReadSecretKey(privateKeyStream);
            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(input.Password.ToCharArray());
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();

            sGen.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.CanonicalTextDocument, pgpPrivKey);

            IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            Stream fIn = File.OpenRead(input.InputFile);
            Stream outputStream = File.Create(input.OutputFile);

            ArmoredOutputStream aOut = new ArmoredOutputStream(outputStream);

            aOut.BeginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            MemoryStream lineOut = new MemoryStream();
            int lookAhead = Services.ReadInputLine(lineOut, fIn);

            Services.ProcessLine(aOut, sGen, lineOut.ToArray());

            if (lookAhead != -1)
            {
                do
                {
                    lookAhead = Services.ReadInputLine(lineOut, lookAhead, fIn);

                    sGen.Update((byte)'\r');
                    sGen.Update((byte)'\n');

                    Services.ProcessLine(aOut, sGen, lineOut.ToArray());
                }
                while (lookAhead != -1);
            }

            fIn.Close();

            aOut.EndClearText();

            BcpgOutputStream bOut = new BcpgOutputStream(aOut);

            sGen.Generate().Encode(bOut);

            aOut.Close();
            outputStream.Close();

            PgpClearTextSignatureResult ret = new PgpClearTextSignatureResult
            {
                FilePath = input.OutputFile
            };

            return ret;
        }

        #endregion

        #region PgpVerifyFileClearTextSignature 
        /// <summary>
        /// Verifies clear text PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifyClearTextSignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static PgpVerifyClearTextSignatureResult PgpVerifyFileClearTextSignature(PgpVerifyClearTextSignatureInput input)
        {
            using (var inStr = File.OpenRead(input.InputFile))
            using (var outStr = File.Create(input.OutputFile))
            using (var keyStr = PgpUtilities.GetDecoderStream(File.OpenRead(input.PublicKeyFile)))
            {
                ArmoredInputStream aInputStr = new ArmoredInputStream(inStr);

                //
                // write out signed section using the local line separator.
                // note: trailing white space needs to be removed from the end of
                // each line RFC 4880 Section 7.1
                //
                MemoryStream lineOut = new MemoryStream();
                int lookAhead = Services.PgpVerifyClearTextSignatureReadInputLine(lineOut, aInputStr);
                byte[] lineSep = Encoding.ASCII.GetBytes(Environment.NewLine); ;


                if (lookAhead != -1 && aInputStr.IsClearText())
                {
                    byte[] line = lineOut.ToArray();
                    outStr.Write(line, 0, Services.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(lineSep, 0, lineSep.Length);

                    while (lookAhead != -1 && aInputStr.IsClearText())
                    {
                        lookAhead = Services.PgpVerifyClearTextSignatureReadInputLine(lineOut, lookAhead, aInputStr);

                        line = lineOut.ToArray();
                        outStr.Write(line, 0, Services.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStr.Write(lineSep, 0, lineSep.Length);
                    }
                }
                else
                {
                    // a single line file
                    if (lookAhead != -1)
                    {
                        byte[] line = lineOut.ToArray();
                        outStr.Write(line, 0, Services.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStr.Write(lineSep, 0, lineSep.Length);
                    }
                }
                outStr.Close();

                PgpPublicKeyRingBundle pgpRings = new PgpPublicKeyRingBundle(keyStr);

                PgpObjectFactory pgpFact = new PgpObjectFactory(aInputStr);
                PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                PgpSignature sig = p3[0];
                inStr.Close();


                sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));
                // read the input, making sure we ignore the last newline.
                bool verified = false;
                using (var sigIn = File.OpenRead(input.OutputFile))
                {
                    lookAhead = Services.PgpVerifyClearTextSignatureReadInputLine(lineOut, sigIn);
                    Services.ProcessLine(sig, lineOut.ToArray());
                    if (lookAhead != -1)
                    {
                        do
                        {
                            lookAhead = Services.PgpVerifyClearTextSignatureReadInputLine(lineOut, lookAhead, sigIn);

                            sig.Update((byte)'\r');
                            sig.Update((byte)'\n');

                            Services.ProcessLine(sig, lineOut.ToArray());
                        }
                        while (lookAhead != -1);
                    }

                    verified = sig.Verify();
                    sigIn.Close();
                }
                PgpVerifyClearTextSignatureResult ret = new PgpVerifyClearTextSignatureResult
                {
                    FilePath = input.OutputFile,
                    Verified = verified
                };

                return ret;
            }
        }

        #endregion

    }

}