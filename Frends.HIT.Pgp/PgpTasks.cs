using System;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities.IO;
using System.Text;
using Frends.HIT.Pgp.Handlers;

#pragma warning disable 1591

namespace Frends.HIT.Pgp
{

    public class PgpTasks
    {
        internal const int EncryptBufferSize = 1 << 16;

        #region PgpDecryptFile

        /// <summary>
        /// Decrypt the file using the private key.
        /// </summary>
        public static PgpDecryptResult DecryptFile(PgpDecryptInput input)
        {
            DecryptHandler decryptHandler = new DecryptHandler(input);

            using (var inputStream = decryptHandler.InputStream())
            {
                using (var keyIn = decryptHandler.KeyStream())
                {
                    Decrypt(inputStream, keyIn, decryptHandler.PassPhrase, out var output);
                    decryptHandler.Output = output;
                }
            }
            return new PgpDecryptResult
            {
                Output = decryptHandler.Output
            };
        }

        internal static bool Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, out string output)
        {
            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            var pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            var pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
            var o = pgpF.NextPgpObject();

            PgpEncryptedDataList enc;
            // the first object might be a PGP marker packet.
            if (o is PgpEncryptedDataList list)
                enc = list;
            else
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

            // decrypt
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                sKey = PgpServices.FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (sKey == null) continue;
                pbe = pked;
                break;
            }

            if (sKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact;

            using (var clear = pbe.GetDataStream(sKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            var message = plainFact.NextPgpObject();

            // Some messages start with a signature list, which we need to get over
            // to get to the actual content of the message. Signature verification
            // should be done by VerifyFileSignature task.
            if (message is PgpSignatureList)
                message = plainFact.NextPgpObject();

            switch (message)
            {
                case PgpCompressedData cData:
                {
                    PgpObjectFactory of;

                    using (var compDataIn = cData.GetDataStream())
                    {
                        of = new PgpObjectFactory(compDataIn);
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        message = of.NextPgpObject();
                        var ld = (PgpLiteralData)message;
                        using (var outputStream = new MemoryStream())
                        {
                            var unc = ld.GetInputStream();
                            Streams.PipeAll(unc, outputStream);
                            outputStream.Position = 0;
                            using var reader = new StreamReader(outputStream);
                            output = reader.ReadToEnd();
                        }
                    }
                    else
                    {
                        var ld = (PgpLiteralData)message;
                        using (var outputStream = new MemoryStream())
                        {
                            var unc = ld.GetInputStream();
                            Streams.PipeAll(unc, outputStream);
                            outputStream.Position = 0;
                            using var reader = new StreamReader(outputStream);
                            output = reader.ReadToEnd();
                        }
                    }

                    break;
                }
                case PgpLiteralData ld:
                {
                    using (var fOut = new MemoryStream())
                    {
                        var unc = ld.GetInputStream();
                        Streams.PipeAll(unc, fOut);
                        fOut.Position = 0;
                        using var reader = new StreamReader(fOut);
                        output = reader.ReadToEnd();
                    }

                    break;
                }
                case PgpOnePassSignatureList _:
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                default:
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

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
        public static PgpEncryptResult EncryptFile(PgpEncryptInput input)
        {
            var encryptionHandlers = new EncryptionHandler(input);

            using var outputStream = new MemoryStream();
            using (var armoredStream = input.UseArmor ? (Stream)new ArmoredOutputStream(outputStream) : outputStream)
            using (var encryptedOut = PgpServices.GetEncryptionStream(armoredStream, encryptionHandlers))
            using (var compressedOut = PgpServices.GetCompressionStream(encryptedOut, encryptionHandlers))
            {
                // signature init - if necessary
                var signatureGenerator = input.SignWithPrivateKey ? PgpServices.InitPgpSignatureGenerator(compressedOut, encryptionHandlers) : null;

                // writing to configured output
                var literalDataGenerator = new PgpLiteralDataGenerator();
                using (var literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, encryptionHandlers.Name, encryptionHandlers.Length, DateTime.Now))
                {
                    using var inputStream = encryptionHandlers.InputStream();
                    var buf = new byte[EncryptBufferSize];
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
            outputStream.Position = 0;
            using (var reader = new StreamReader(outputStream))
            {
                return new PgpEncryptResult
                {
                    Output = reader.ReadToEnd()
                };
            }
        }

        #endregion

        #region PgpSignFile

        /// <summary>
        /// Sign a file with PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpSignature Returns: Object {string FilePath}
        /// </summary>
        public static PgpSignatureResult SignFile(PgpSignatureInput input)
        {
            var signatureHandler = new SignatureHandler(input);
            var digest = signatureHandler.HashFunction.ConvertEnum<HashAlgorithmTag>();

            using (var privateKeyStream = signatureHandler.KeyStream())
            {
                var pgpSecKey = PgpServices.SignatureReadSecretKey(privateKeyStream);
                var pgpPrivKey = pgpSecKey.ExtractPrivateKey(signatureHandler.GetPassword().ToCharArray());
                var signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
                var signatureSubpacketGenerator = new PgpSignatureSubpacketGenerator();

                signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

                var enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
                if (enumerator.MoveNext())
                {
                    signatureSubpacketGenerator.SetSignerUserId(false, (string)enumerator.Current);
                    signatureGenerator.SetHashedSubpackets(signatureSubpacketGenerator.Generate());
                }

                using (var outputStream = new MemoryStream())
                {
                    var armoredOutputStream = new ArmoredOutputStream(outputStream);

                    var bcbgOutputStream = new BcpgOutputStream(armoredOutputStream);
                    signatureGenerator.GenerateOnePassVersion(false).Encode(bcbgOutputStream);
                    
                    var literalDataGenerator = new PgpLiteralDataGenerator();
                    var literalDataOut = literalDataGenerator.Open(bcbgOutputStream, PgpLiteralData.Binary, signatureHandler.Name, signatureHandler.Length, DateTime.Now);
                    using (var fileIn = signatureHandler.InputStream())
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
                        
                        outputStream.Position = 0;
                        using var reader = new StreamReader(outputStream);
                        return new PgpSignatureResult
                        {
                            Output = reader.ReadToEnd()
                        };
                        
                    }
                }
            }
        }

        #endregion

        #region PgpVerifyFileSignature
        /// <summary>
        /// Verifies a PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifySignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static PgpVerifySignatureResult VerifyFileSignature(PgpVerifySignatureInput input)
        {
            var verifySignatureHandler = new VerifySignatureHandler(input);
            using (var inputStream = PgpUtilities.GetDecoderStream(verifySignatureHandler.InputStream()))
            using (var keyStream = PgpUtilities.GetDecoderStream(verifySignatureHandler.KeyStream()))
            {
                var pgpFact = new PgpObjectFactory(inputStream);
                var signatureList = (PgpOnePassSignatureList)pgpFact.NextPgpObject();

                if (signatureList == null)
                {
                    throw new Exception("Can't find signature in file.");
                }

                var onePassSignature = signatureList[0];



                var p2 = (PgpLiteralData)pgpFact.NextPgpObject();
                var dataIn = p2.GetInputStream();
                var pgpRing = new PgpPublicKeyRingBundle(keyStream);
                var key = pgpRing.GetPublicKey(onePassSignature.KeyId);
                
                using (var outputStream = verifySignatureHandler.OutputStream(p2.FileName))
                {
                    onePassSignature.InitVerify(key);

                    int ch;
                    while ((ch = dataIn.ReadByte()) >= 0)
                    {
                        onePassSignature.Update((byte)ch);
                        outputStream.WriteByte((byte)ch);
                    }

                    if (outputStream is MemoryStream)
                    {
                        outputStream.Position = 0;
                        using var reader = new StreamReader(outputStream);
                        verifySignatureHandler.Output = reader.ReadToEnd();
                    }
                    outputStream.Close();
                }

                bool verified;
                // Will throw Exception if file is altered
                try
                {
                    var p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                    var firstSig = p3[0];
                    verified = onePassSignature.Verify(firstSig);
                }
                catch (Exception)
                {
                    return new PgpVerifySignatureResult
                    {
                        Output = verifySignatureHandler.GetOutput(),
                        Verified = false
                    };
                }

                return new PgpVerifySignatureResult
                {
                    Output = verifySignatureHandler.GetOutput(),
                    Verified = verified
                };
            }
        }

        #endregion

        #region PgpClearTextSignFile
        /// <summary>
        /// Create a file with PGP clear text signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpClearTextSignature Returns: Object {string FilePath}
        /// </summary>
        public static PgpClearTextSignatureResult ClearTextSignFile(PgpClearTextSignatureInput input)
        {
            var clearTextSignatureHandler = new ClearTextSignatureHandler(input);
            var digest = clearTextSignatureHandler.HashFunction switch
            {
                PgpClearTextSignatureHashFunctionType.Md5 => HashAlgorithmTag.MD5,
                PgpClearTextSignatureHashFunctionType.RipeMd160 => HashAlgorithmTag.RipeMD160,
                PgpClearTextSignatureHashFunctionType.Sha1 => HashAlgorithmTag.Sha1,
                PgpClearTextSignatureHashFunctionType.Sha224 => HashAlgorithmTag.Sha224,
                PgpClearTextSignatureHashFunctionType.Sha384 => HashAlgorithmTag.Sha384,
                PgpClearTextSignatureHashFunctionType.Sha512 => HashAlgorithmTag.Sha512,
                PgpClearTextSignatureHashFunctionType.Sha256 => HashAlgorithmTag.Sha256,
                _ => HashAlgorithmTag.Sha256
            };

            var privateKeyStream = clearTextSignatureHandler.KeyStream();

            var pgpSecKey = PgpServices.ReadSecretKey(privateKeyStream);
            var pgpPrivKey = pgpSecKey.ExtractPrivateKey(clearTextSignatureHandler.GetPassword().ToCharArray());
            var sGen = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, digest);
            var spGen = new PgpSignatureSubpacketGenerator();

            sGen.InitSign(PgpSignature.CanonicalTextDocument, pgpPrivKey);

            var enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator();
            if (enumerator.MoveNext())
            {
                spGen.SetSignerUserId(false, (string)enumerator.Current);
                sGen.SetHashedSubpackets(spGen.Generate());
            }

            using var fIn = clearTextSignatureHandler.InputStream();
            using var outputStream = new MemoryStream();
            using var aOut = new ArmoredOutputStream(outputStream);
            aOut.BeginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            var lineOut = new MemoryStream();
            var lookAhead = PgpServices.ReadInputLine(lineOut, fIn);

            PgpServices.ProcessLine(aOut, sGen, lineOut.ToArray());

            while (lookAhead != -1)
            {
                lookAhead = PgpServices.ReadInputLine(lineOut, lookAhead, fIn);

                sGen.Update((byte)'\r');
                sGen.Update((byte)'\n');

                PgpServices.ProcessLine(aOut, sGen, lineOut.ToArray());
            }

            aOut.EndClearText();

            var bOut = new BcpgOutputStream(aOut);

            sGen.Generate().Encode(bOut);
            aOut.Close();
            
            outputStream.Position = 0;
            using var reader = new StreamReader(outputStream);
            return new PgpClearTextSignatureResult
            {
                Output = reader.ReadToEnd()
            };
        }

        #endregion

        #region PgpVerifyFileClearTextSignature 
        /// <summary>
        /// Verifies clear text PGP signature. See documentation at https://github.com/CommunityHiQ/Frends.Community.PgpVerifyClearTextSignature Returns: Object {string FilePath, Boolean Verified}
        /// </summary>
        public static PgpVerifyClearTextSignatureResult VerifyFileClearTextSignature(PgpVerifyClearTextSignatureInput input)
        {
            var verifyClearTextSignatureHandler = new VerifyClearTextSignatureHandler(input);
            using (var inStr = verifyClearTextSignatureHandler.InputStream())
            using (var outStr = new MemoryStream())
            using (var keyStr = PgpUtilities.GetDecoderStream(verifyClearTextSignatureHandler.KeyStream()))
            {
                var aInputStr = new ArmoredInputStream(inStr);

                //
                // write out signed section using the local line separator.
                // note: trailing white space needs to be removed from the end of
                // each line RFC 4880 Section 7.1
                //
                var lineOut = new MemoryStream();
                var lookAhead = PgpServices.VerifyClearTextSignatureReadInputLine(lineOut, aInputStr);
                var lineSep = Encoding.ASCII.GetBytes(Environment.NewLine); 


                if (lookAhead != -1 && aInputStr.IsClearText())
                {
                    var line = lineOut.ToArray();
                    outStr.Write(line, 0, PgpServices.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outStr.Write(lineSep, 0, lineSep.Length);

                    while (lookAhead != -1 && aInputStr.IsClearText())
                    {
                        lookAhead = PgpServices.VerifyClearTextSignatureReadInputLine(lineOut, lookAhead, aInputStr);

                        line = lineOut.ToArray();
                        outStr.Write(line, 0, PgpServices.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStr.Write(lineSep, 0, lineSep.Length);
                    }
                }
                else
                {
                    // a single line file
                    if (lookAhead != -1)
                    {
                        var line = lineOut.ToArray();
                        outStr.Write(line, 0, PgpServices.GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        outStr.Write(lineSep, 0, lineSep.Length);
                    }
                }

                outStr.Position = 0;
                using (var reader = new StreamReader(outStr))
                {
                    verifyClearTextSignatureHandler.Output = reader.ReadToEnd();
                }
                outStr.Close();

                var pgpRings = new PgpPublicKeyRingBundle(keyStr);

                var pgpFact = new PgpObjectFactory(aInputStr);
                var p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                var sig = p3[0];
                inStr.Close();


                sig.InitVerify(pgpRings.GetPublicKey(sig.KeyId));
                // read the input, making sure we ignore the last newline.
                bool verified;
                using (var sigIn = verifyClearTextSignatureHandler.OutputStream())
                {
                    lookAhead = PgpServices.VerifyClearTextSignatureReadInputLine(lineOut, sigIn);
                    PgpServices.ProcessLine(sig, lineOut.ToArray());
                    while (lookAhead != -1)
                    {
                        lookAhead = PgpServices.VerifyClearTextSignatureReadInputLine(lineOut, lookAhead, sigIn);

                        sig.Update((byte)'\r');
                        sig.Update((byte)'\n');

                        PgpServices.ProcessLine(sig, lineOut.ToArray());
                    }

                    verified = sig.Verify();
                    sigIn.Close();
                }
                return new PgpVerifyClearTextSignatureResult
                {
                    Output = verifyClearTextSignatureHandler.Output,
                    Verified = verified
                };
            }
        }

        #endregion
    }

}