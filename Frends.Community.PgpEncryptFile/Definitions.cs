using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.PgpEncrypt
{
    /// <summary>
    /// Input for Encrypt task
    /// </summary>
    public class Input
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
        /// Encryption algorithm to use
        /// </summary>
        [DefaultValue(EncryptionAlgorithm.Cast5)]
        public EncryptionAlgorithm EncryptionAlgorithm { get; set; }

        /// <summary>
        /// Type of compression to use
        /// </summary>
        [DefaultValue(CompressionType.Zip)]
        public CompressionType CompressionType { get; set; }

        /// <summary>
        /// Use ascii armor or not.
        /// </summary>
        [DefaultValue("true")]
        public bool UseArmor { get; set; }
        
        /// <summary>
        /// Check integrity of output file or not.
        /// </summary>
        [DefaultValue("true")]
        public bool UseIntegrityCheck { get; set; }

        /// <summary>
        /// Should the encrypted file be signed with private key?
        /// </summary>
        public bool SignWithPrivateKey { get; set; }

        /// <summary>
        /// File signing related settings
        /// </summary>
        [UIHint(nameof(SignWithPrivateKey), "", true)]
        public SigningSettings SigningSettings { get; set; }
    }

    /// <summary>
    /// Settings related to signing
    /// </summary>
    public class SigningSettings
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
        [DefaultValue(SignatureHashAlgorithm.Sha1)]
        public SignatureHashAlgorithm SignatureHashAlgorithm { get; set; }
    }

    /// <summary>
    /// Result class.
    /// </summary>
    public class Result
    {
        public string FilePath { get; set; }
    }

    /// <summary>
    /// Encryption algorithm to use
    /// </summary>
    public enum EncryptionAlgorithm
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
    public enum CompressionType
    {
        BZip2,
        Uncompressed,
        Zip,
        ZLib
    }

    /// <summary>
    /// Signature hash algorithm to use
    /// </summary>
    public enum SignatureHashAlgorithm
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
}
