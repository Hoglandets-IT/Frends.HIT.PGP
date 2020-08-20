
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

#pragma warning disable 1591

namespace FRENDS.Community.Pgp
{

    #region PgpClearTextSignature
    public class PgpClearTextSignatureInput
    {
        /// <summary>
        /// Path to file being signed.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }
        /// <summary>
        /// Path to signed file that will be created.
        /// </summary>
        [DefaultValue(@"C:\temp\encryptedFile.pgp")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFile { get; set; }
        /// <summary>
        /// Path to private key file.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PrivateKeyFile { get; set; }
        /// <summary>
        /// Password attached to private key.
        /// </summary>
        [PasswordPropertyText]
        public string Password { get; set; }
        /// <summary>
        /// Hash (digest) function, such as SHA256, SHA384, SHA512, MD5, RIPEMD160, SHA1.
        /// </summary>
        // public HashAlgorithmTag HashFunction { get; set; }
        [DefaultValue(PgpClearTextSignatureHashFunctionType.Sha256)]
        public PgpClearTextSignatureHashFunctionType HashFunction { get; set; }
    }

    /// <summary>
    /// Enum for choosing HashAlgorithm type.
    /// </summary>
    public enum PgpClearTextSignatureHashFunctionType
    {
        MD5,
        Sha1,
        RipeMD160,
        Sha224,
        Sha256,
        Sha384,
        Sha512
    }


    public class PgpClearTextSignatureResult
    {
        /// <summary>
        /// Result class.
        /// </summary>
        public string FilePath { get; set; }
    }
    #endregion

    #region PgpDecrypt

    public class PgpDecryptInput
    {
        /// <summary>
        /// Path to file to decrypt.
        /// </summary>
        [DefaultValue(@"C:\temp\encryptedFile.pgp")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }
        /// <summary>
        /// Path to file that will be create.
        /// </summary>
        [DefaultValue(@"C:\temp\decrypted_file.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFile { get; set; }
        /// <summary>
        /// Private key used to decrypt file.
        /// </summary>
        [DefaultValue(@"C:\temp\privateKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PrivateKeyFile { get; set; }
        /// <summary>
        /// Password for private key.
        /// </summary>
        [PasswordPropertyText]
        public string PassPhrase { get; set; }

    }
    public class PgpDecryptResult
    {
        /// <summary>
        /// Result class.
        /// </summary>
        public string FilePath { get; set; }
    }

    #endregion

    #region PgpEncrypt
    /// <summary>
    /// Input for Encrypt task
    /// </summary>
    public class PgpEncryptInput
    {
        /// <summary>
        /// Path to file being encrypted.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }

        /// <summary>
        /// Path to encrypted file that will be create.
        /// </summary>
        [DefaultValue(@"C:\temp\encryptedFile.pgp")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFile { get; set; }

        /// <summary>
        /// Path to recipients public key.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PublicKeyFile { get; set; }

        /// <summary>
        /// Use ascii armor or not.
        /// </summary>
        [DefaultValue(true)]
        public bool UseArmor { get; set; }

        /// <summary>
        /// Check integrity of output file or not.
        /// </summary>
        [DefaultValue(true)]
        public bool UseIntegrityCheck { get; set; }

        /// <summary>
        /// Should compression be used?
        /// </summary>
        [DefaultValue(true)]
        public bool UseCompression { get; set; }

        /// <summary>
        /// Type of compression to use
        /// </summary>
        [DefaultValue(PgpEncryptCompressionType.Zip)]
        [UIHint(nameof(UseCompression), "", true)]
        public PgpEncryptCompressionType CompressionType { get; set; }

        /// <summary>
        /// Encryption algorithm to use
        /// </summary>
        [DefaultValue(PgpEncryptEncryptionAlgorithm.Cast5)]
        public PgpEncryptEncryptionAlgorithm EncryptionAlgorithm { get; set; }

        /// <summary>
        /// Should the encrypted file be signed with private key?
        /// </summary>
        public bool SignWithPrivateKey { get; set; }

        /// <summary>
        /// File signing related settings
        /// </summary>
        [UIHint(nameof(SignWithPrivateKey), "", true)]
        public PgpEncryptSigningSettings SigningSettings { get; set; }
    }

    /// <summary>
    /// Settings related to signing
    /// </summary>
    public class PgpEncryptSigningSettings
    {
        /// <summary>
        /// Path to private key to sign with
        /// </summary>
        [DefaultValue(@"C:\temp\privateKeyFile.gpg")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PrivateKeyFile { get; set; }

        /// <summary>
        /// If the file should be signed with private key then password to private key has to be offered
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }

        /// <summary>
        /// Hash algorithm to use with signature
        /// </summary>
        [DefaultValue(PgpEncryptSignatureHashAlgorithm.Sha1)]
        public PgpEncryptSignatureHashAlgorithm SignatureHashAlgorithm { get; set; }
    }

    /// <summary>
    /// Result class.
    /// </summary>
    public class PgpEncryptResult
    {
        public string FilePath { get; set; }
    }

    /// <summary>
    /// Encryption algorithm to use
    /// </summary>
    public enum PgpEncryptEncryptionAlgorithm
    {
        Aes128,
        Aes192,
        Aes256,
        Blowfish,
        Camellia128,
        Camellia192,
        Camellia256,
        Cast5,
        Des,
        Idea,
        TripleDes,
        Twofish
    }

    /// <summary>
    /// Compression to use
    /// </summary>
    public enum PgpEncryptCompressionType
    {
        BZip2,
        Uncompressed,
        Zip,
        ZLib
    }

    /// <summary>
    /// Signature hash algorithm to use
    /// </summary>
    public enum PgpEncryptSignatureHashAlgorithm
    {
        MD2,
        MD5,
        RipeMD160,
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512
    }
    #endregion

    #region PgpSignature
    public class PgpSignatureInput
    {
        /// <summary>
        /// Path to file to sign.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }
        /// <summary>
        /// Path to signed file that will be created.
        /// </summary>
        [DefaultValue(@"C:\temp\signature.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFile { get; set; }
        /// <summary>
        /// Path to private key file.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PrivateKeyFile { get; set; }
        /// <summary>
        /// Password attached to private key.
        /// </summary>
        [PasswordPropertyText]
        public string Password { get; set; }
        /// <summary>
        /// Hash (digest) function, such as SHA256, SHA384, SHA512, MD5, RIPEMD160, SHA1.
        /// </summary>
        // public HashAlgorithmTag HashFunction { get; set; }
        [DefaultValue(PgpSignatureHashFunctionType.Sha256)]
        public PgpSignatureHashFunctionType HashFunction { get; set; }
    }

    /// <summary>
    /// Enum for choosing HashAlgorithm type.
    /// </summary>
    public enum PgpSignatureHashFunctionType
    {
        MD5,
        Sha1,
        RipeMD160,
        Sha224,
        Sha256,
        Sha384,
        Sha512
    }


    public class PgpSignatureResult
    {
        /// <summary>
        /// Result class.
        /// </summary>
        public string FilePath { get; set; }
    }


    #endregion


# region PgpVerifyClearTextSignature
    public class PgpVerifyClearTextSignatureInput
    {
        /// <summary>
        /// Path to file to verify.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }

        /// <summary>
        /// Path to public key file.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PublicKeyFile { get; set; }

        /// <summary>
        /// Path for verified result file.
        /// </summary>
        [DefaultValue(@"C:\temp\message_out.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFile { get; set; }

    }

    public class PgpVerifyClearTextSignatureResult
    {
        /// <summary>
        /// Path to verified file.
        /// </summary>
        public string FilePath { get; set; }
        /// <summary>
        /// False if verification fails
        /// </summary>
        [DefaultValue("false")]
        public Boolean Verified { get; set; }
    }

    #endregion

    #region PgpVerifySignature
    public class PgpVerifySignatureInput
    {
        /// <summary>
        /// Path to signed file.
        /// </summary>
        [DefaultValue(@"C:\temp\message.txt")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputFile { get; set; }

        /// <summary>
        /// Path to public key file.
        /// </summary>
        [DefaultValue(@"C:\temp\publicKey.asc")]
        [DisplayFormat(DataFormatString = "Text")]
        public string PublicKeyFile { get; set; }

        /// <summary>
        /// Folder where the verified file will be created. 
        /// If empty, file will be created to same folder as InputFile
        /// </summary>
        [DefaultValue(@"")]
        [DisplayFormat(DataFormatString = "Text")]
        public string OutputFolder { get; set; }


    }


    public class PgpVerifySignatureResult
    {
        /// <summary>
        /// Path to verified file.
        /// </summary>
        public string FilePath { get; set; }
        /// <summary>
        /// False if verification fails
        /// </summary>
        [DefaultValue("false")]
        public Boolean Verified { get; set; }
    }

    #endregion

}