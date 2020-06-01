using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

#pragma warning disable 1591

namespace FRENDS.Community.PgpVerifyClearTextSignature
{
    public class Input
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

    public class Result
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

}