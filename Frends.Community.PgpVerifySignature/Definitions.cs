using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

#pragma warning disable 1591

namespace FRENDS.Community.PgpVerifySignature
{
    public class Input
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